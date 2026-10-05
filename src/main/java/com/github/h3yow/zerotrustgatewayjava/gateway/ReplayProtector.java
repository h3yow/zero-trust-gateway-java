package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 防重放 / 防篡改判定（全部状态在本地内存）：
 * <ol>
 *   <li>请求必须携带唯一 requestId，缺失 → {@code MISSING_REQUEST_ID}；</li>
 *   <li>必须携带毫秒时间戳，缺失 → {@code MISSING_TIMESTAMP}；超出允许偏差 →
 *       {@code TIMESTAMP_OUT_OF_WINDOW}；</li>
 *   <li>同一主体的 requestId 只在“该请求自身的时间窗口”（{@code timestamp + skew}）内占用一次：
 *       窗口内重复提交（含并发重放）→ {@code REPLAYED_REQUEST}；越过窗口的陈旧记录会被到期清理，
 *       不再拦截之后的新请求；</li>
 *   <li>(timestamp, sequence) 必须严格单调递增，时间或序号回退 →
 *       {@code SEQUENCE_REGRESSION}；</li>
 *   <li>每主体有效记录数有明确容量上限：先清过期、仍达上限时新请求 →
 *       {@code REPLAY_STORE_FULL}。不会静默放过，也不会淘汰仍在有效期内的记录来“腾位置”。</li>
 * </ol>
 *
 * <p>时效与容量收敛：每个主体一把锁，“到期清理 + 查重 + 容量判定 + 登记”在同一临界区原子完成。
 * 到期队列按过期时间升序，清理为摊销 O(1)，查重为 O(1)，长期高吞吐下记录规模受
 * “窗口 × 容量”双重约束，不会只增不减，判定耗时稳定。
 * 只有通过全部检查的请求才会登记 ID 并推进水位，被拒请求不会污染状态。
 *
 * <p>判定与提交可分离：{@link #precheck} 只读预判、{@link #commit} 重新判定并提交，
 * 供网关在“主体准入锁”内把限流判定夹在两者之间，使重复请求在配额判定时完全不占位；
 * 单独使用的 {@link #check} 语义不变（判定 + 提交一步完成）。
 */
@Component
public class ReplayProtector {

    private static final Logger log = LoggerFactory.getLogger(ReplayProtector.class);

    private final GatewayProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, SubjectState> states = new ConcurrentHashMap<>();

    @Autowired
    public ReplayProtector(GatewayProperties properties) {
        this(properties, Clock.systemUTC());
    }

    /** 可注入时钟，仅供测试精确控制时效边界；生产装配使用系统时钟。 */
    public ReplayProtector(GatewayProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** 校验通过返回 null；否则返回可区分的拒绝原因。等价于 precheck 通过后立即 commit。 */
    public RejectionReason check(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();
        RejectionReason headerMiss = missingHeaderReason(request);
        if (headerMiss != null) {
            return headerMiss;
        }
        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());
        synchronized (state) {
            RejectionReason verdict = evaluateLocked(state, subject, request);
            if (verdict != null) {
                return verdict;
            }
            commitLocked(state, request);
            return null;
        }
    }

    /**
     * 只读预判（不登记 ID、不推进水位）：与 {@link #check} 完全相同的判定规则，
     * 但通过后不提交任何状态。配合 {@link #commit} 使用，调用方必须保证同一主体下
     * “precheck -> （限流等中间判定） -> commit” 整体串行（见 ZeroTrustGateway 的主体准入锁），
     * 使 commit 时状态与 precheck 一致，commit 必然成功。
     * 用途：让“窗口内重复/序号回退/容量满”在被限流判定之前就给出确定结论——
     * 重复请求即使配额已满也稳定判 REPLAYED_REQUEST，且全程不触碰配额。
     */
    public RejectionReason precheck(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();
        RejectionReason headerMiss = missingHeaderReason(request);
        if (headerMiss != null) {
            return headerMiss;
        }
        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());
        synchronized (state) {
            return evaluateLocked(state, subject, request);
        }
    }

    /**
     * 提交登记：重新完整判定（与 {@link #check} 相同），通过后原子登记 ID 并推进水位。
     * 在主体准入锁内调用时，若此前的 {@link #precheck} 已通过则此处必然通过；
     * 重新判定是兜底，保证任何调用路径下都不会跳过检查直接登记。
     */
    public RejectionReason commit(CallerPrincipal principal, GatewayRequest request) {
        return check(principal, request);
    }

    private static RejectionReason missingHeaderReason(GatewayRequest request) {
        if (request.requestId() == null || request.requestId().isBlank()) {
            return RejectionReason.MISSING_REQUEST_ID;
        }
        if (request.timestamp() == null) {
            return RejectionReason.MISSING_TIMESTAMP;
        }
        return null;
    }

    /** 临界区内的完整判定（调用方须已持有 state 监视器锁）；通过返回 null，不产生任何提交。 */
    private RejectionReason evaluateLocked(SubjectState state, String subject, GatewayRequest request) {
        long now = clock.millis();
        long skew = properties.getTimestampSkewMillis();
        long ts = request.timestamp();
        if (ts < now - skew || ts > now + skew) {
            log.warn("时间窗口拒绝: subject={}, ts={}, now={}, skew={}", subject, ts, now, skew);
            return RejectionReason.TIMESTAMP_OUT_OF_WINDOW;
        }
        String requestId = request.requestId();

        // 1) 时效收敛：清理越过窗口的陈旧记录（expiry 基于请求自身时间戳 ts+skew）
        int evicted = state.evictExpired(now);
        if (evicted > 0) {
            log.info("重放记录时效清理: subject={}, evicted={}, retained={}",
                    subject, evicted, state.seenIds.size());
        }

        // 2) 窗口内重放一律拦截（陈旧记录已在上一步移除，不会误伤窗口后的新请求）
        if (state.seenIds.containsKey(requestId)) {
            long expiry = state.seenIds.get(requestId);
            log.warn("重放拒绝: subject={}, requestId={}, expiresAt={}, now={}",
                    subject, requestId, expiry, now);
            return RejectionReason.REPLAYED_REQUEST;
        }

        // 3) 单调水位：先比时间戳，相同时间戳再比序号；未携带序号时只要求时间戳不回退
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

        // 4) 容量收敛：过期记录已清完仍达上限 → 明确拒绝，不静默放过、不淘汰有效记录
        int max = properties.getReplayMaxIdsPerSubject();
        if (state.seenIds.size() >= max) {
            log.warn("重放容量拒绝: subject={}, retained={}, capacity={}, requestId={}",
                    subject, state.seenIds.size(), max, requestId);
            return RejectionReason.REPLAY_STORE_FULL;
        }
        return null;
    }

    /** 临界区内的提交（调用方须已持有 state 监视器锁且判定已通过）：登记 ID + 推进水位。 */
    private void commitLocked(SubjectState state, GatewayRequest request) {
        long skew = properties.getTimestampSkewMillis();
        long ts = request.timestamp();
        long expiry = ts + skew;
        state.seenIds.put(request.requestId(), expiry);
        state.expiryQueue.addLast(new ExpiryEntry(expiry, request.requestId()));
        state.lastTimestamp = ts;
        if (request.sequence() != null) {
            state.lastSequence = request.sequence();
        }
    }

    /** 某主体当前仍在有效期内的重放记录数（供测试观察容量/时效收敛）。 */
    public int trackedCount(String subjectId) {
        SubjectState state = states.get(subjectId);
        if (state == null) {
            return 0;
        }
        synchronized (state) {
            return state.seenIds.size();
        }
    }

    /** 仅供测试：清空状态。 */
    public void reset() {
        states.clear();
    }

    private record ExpiryEntry(long expiry, String requestId) {
    }

    private static final class SubjectState {
        /** requestId -> 过期时间（epochMillis，= 请求时间戳 + skew）。 */
        private final Map<String, Long> seenIds = new ConcurrentHashMap<>();
        /** 按过期时间升序的到期队列，用于摊销 O(1) 清理。 */
        private final ArrayDeque<ExpiryEntry> expiryQueue = new ArrayDeque<>();
        private long lastTimestamp = Long.MIN_VALUE;
        private Long lastSequence;

        int evictExpired(long now) {
            int removed = 0;
            ExpiryEntry head;
            while ((head = expiryQueue.peekFirst()) != null && head.expiry() < now) {
                expiryQueue.pollFirst();
                // 同一 requestId 在窗口内不会二次登记；仅当 map 中仍是该到期记录时才删除
                if (Long.valueOf(head.expiry()).equals(seenIds.get(head.requestId()))) {
                    seenIds.remove(head.requestId());
                    removed++;
                }
            }
            return removed;
        }
    }
}
