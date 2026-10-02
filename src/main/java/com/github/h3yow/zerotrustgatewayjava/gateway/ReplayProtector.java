package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 防重放 / 防篡改判定（全部状态在本地内存）：
 * <ol>
 *   <li>请求必须携带唯一 requestId，缺失 → {@code MISSING_REQUEST_ID}；</li>
 *   <li>必须携带毫秒时间戳，缺失 → {@code MISSING_TIMESTAMP}；超出允许偏差 →
 *       {@code TIMESTAMP_OUT_OF_WINDOW}；</li>
 *   <li>同一主体的 requestId 只在对应时间窗口（timestamp + skew）内占用：
 *       越过窗口的陈旧记录每次判定时按最小过期堆即时回收，回收后同一 requestId
 *       可作为新请求再次使用，记录规模按时效收敛；</li>
 *   <li>窗口内重复提交（含并发重放）→ {@code REPLAYED_REQUEST}；</li>
 *   <li>(timestamp, sequence) 必须严格单调递增，时间或序号回退 →
 *       {@code SEQUENCE_REGRESSION}；</li>
 *   <li>每主体有效记录数有硬上限 {@code replayMaxRecordsPerSubject}；达到上限时：
 *       先回收已过期记录，回收后仍无空位则 {@code REPLAY_CAPACITY_EXCEEDED}
 *       （fail-closed：不静默放过，也绝不驱逐仍在有效期内的记录）。</li>
 * </ol>
 *
 * <p><b>检查与登记分离</b>：{@link #check} 只判定不留痕；只有真正将被放行的请求
 * 才调用 {@link #commit} 登记 ID 并推进水位。因此鉴权失败、重放拒绝、限流拒绝
 * （含被限流后拿同一请求重试）都不会占用去重名额、不会推进序号水位。
 *
 * <p><b>耗时稳定性</b>：每主体独立锁，“过期回收 + 查重 + 水位比较”在同一临界区
 * 原子完成。查重为 O(1) 哈希查找；过期回收入口只看最小堆堆顶（O(1)），每个条目
 * 一生只入堆/出堆各一次，回收成本均摊 O(log n)，长期高吞吐下单次判定耗时稳定。
 */
@Component
public class ReplayProtector {

    private static final Logger log = LoggerFactory.getLogger(ReplayProtector.class);

    private final GatewayProperties properties;
    private final GatewayClock clock;
    private final ConcurrentHashMap<String, SubjectState> states = new ConcurrentHashMap<>();

    public ReplayProtector(GatewayProperties properties, GatewayClock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /**
     * 只做判定，不修改任何状态（被拒请求不会污染去重表与水位）。
     * 校验通过返回 null；否则返回可区分的拒绝原因。
     */
    public RejectionReason check(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();

        if (request.requestId() == null || request.requestId().isBlank()) {
            return RejectionReason.MISSING_REQUEST_ID;
        }
        if (request.timestamp() == null) {
            return RejectionReason.MISSING_TIMESTAMP;
        }

        long now = clock.nowMillis();
        long skew = properties.getTimestampSkewMillis();
        long ts = request.timestamp();
        if (ts < now - skew || ts > now + skew) {
            log.warn("时间窗口拒绝: subject={}, ts={}, now={}, skew={}", subject, ts, now, skew);
            return RejectionReason.TIMESTAMP_OUT_OF_WINDOW;
        }

        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());
        synchronized (state) {
            int evicted = evictExpired(state, now);
            if (evicted > 0) {
                log.info("重放记录时效收敛: subject={}, 清理过期记录={}, 剩余有效={}",
                        subject, evicted, state.seenIds.size());
            }

            // 窗口内重复：陈旧记录已在上面回收，因此只有仍在有效期内的相同 ID 会命中。
            if (state.seenIds.containsKey(request.requestId())) {
                log.warn("重放拒绝: subject={}, requestId={}", subject, request.requestId());
                return RejectionReason.REPLAYED_REQUEST;
            }

            // 单调水位：先比时间戳，相同时间戳再比序号；未携带序号时只要求时间戳不回退
            if (state.lastTimestamp != Long.MIN_VALUE) {
                boolean regression = ts < state.lastTimestamp
                        || (ts == state.lastTimestamp
                            && request.sequence() != null
                            && state.lastSequence != null
                            && request.sequence() <= state.lastSequence);
                if (regression) {
                    log.warn("序号/时间回退拒绝: subject={}, ts={} (last={}), seq={} (last={})",
                            subject, ts, state.lastTimestamp, request.sequence(), state.lastSequence);
                    return RejectionReason.SEQUENCE_REGRESSION;
                }
            }

            // 容量硬上限：无空位且无过期可回收 → fail-closed，绝不驱逐有效期内记录。
            int max = properties.getReplayMaxRecordsPerSubject();
            if (state.seenIds.size() >= max) {
                log.warn("重放容量保护拒绝: subject={}, 有效记录={}, 上限={}",
                        subject, state.seenIds.size(), max);
                return RejectionReason.REPLAY_CAPACITY_EXCEEDED;
            }
            return null;
        }
    }

    /**
     * 登记一个已通过 {@link #check} 且即将真正放行的请求：写入 ID 并推进水位。
     * 若 check/commit 之间该 ID 被并发抢先提交或容量被占满，仍 fail-closed 拒绝，
     * 保证窗口内重复绝不双放行、记录数绝不超上限。
     */
    public RejectionReason commit(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();
        long expiry = request.timestamp() + properties.getTimestampSkewMillis();

        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());
        synchronized (state) {
            if (state.seenIds.containsKey(request.requestId())) {
                log.warn("提交阶段重放拒绝: subject={}, requestId={}", subject, request.requestId());
                return RejectionReason.REPLAYED_REQUEST;
            }
            int max = properties.getReplayMaxRecordsPerSubject();
            if (state.seenIds.size() >= max) {
                log.warn("提交阶段容量保护拒绝: subject={}, 有效记录={}, 上限={}",
                        subject, state.seenIds.size(), max);
                return RejectionReason.REPLAY_CAPACITY_EXCEEDED;
            }
            state.seenIds.put(request.requestId(), expiry);
            state.expiryQueue.offer(new ExpiryEntry(request.requestId(), expiry));
            // 并发交错提交时水位只增不减，避免晚到的提交把单调水位拉低
            if (request.timestamp() > state.lastTimestamp) {
                state.lastTimestamp = request.timestamp();
            }
            if (request.sequence() != null
                    && (state.lastSequence == null || request.sequence() > state.lastSequence)) {
                state.lastSequence = request.sequence();
            }
            return null;
        }
    }

    /** 仅供测试：清空状态。 */
    public void reset() {
        states.clear();
    }

    /** 仅供测试：某主体当前保留的有效（未过期）requestId 记录数。 */
    public int activeRecordCount(String subjectId) {
        SubjectState state = states.get(subjectId);
        if (state == null) {
            return 0;
        }
        synchronized (state) {
            evictExpired(state, clock.nowMillis());
            return state.seenIds.size();
        }
    }

    /**
     * 按最小过期堆回收陈旧记录：堆顶未过期则立即返回（O(1)）；过期则弹出并同步删除
     * 哈希表条目。每个条目一生只弹出一次，长期运行均摊成本低，不做全表扫描。
     */
    private int evictExpired(SubjectState state, long now) {
        int removed = 0;
        ExpiryEntry head;
        while ((head = state.expiryQueue.peek()) != null && head.expiry() < now) {
            state.expiryQueue.poll();
            // 以哈希表为准，避免重复弹出等异常情况下误删（正常路径两者一致）
            if (state.seenIds.remove(head.requestId(), head.expiry())) {
                removed++;
            }
        }
        return removed;
    }

    private static final class SubjectState {
        /** requestId -> 过期时间（请求 timestamp + skew，epochMillis），查重的事实来源。 */
        private final Map<String, Long> seenIds = new ConcurrentHashMap<>();
        /** 与 seenIds 一一对应的最小过期堆，仅服务于按时效回收。 */
        private final PriorityQueue<ExpiryEntry> expiryQueue = new PriorityQueue<>();
        private long lastTimestamp = Long.MIN_VALUE;
        private Long lastSequence;
    }

    private record ExpiryEntry(String requestId, long expiry) implements Comparable<ExpiryEntry> {
        @Override
        public int compareTo(ExpiryEntry o) {
            return Long.compare(this.expiry, o.expiry);
        }
    }
}
