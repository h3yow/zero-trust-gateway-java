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
 * <p>判定拆成两阶段供网关编排：{@link #inspect} 只读预检（不碰状态提交），
 * {@link #check} 原子复检+登记。二者判定口径一致；预检让“窗口内重复”在占用限流配额之前
 * 就被识别，重复请求永远不会消耗、也不会临时占用配额。
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

    /**
     * 只读预检（不登记、不推进水位）：与 {@link #check} 完全相同的判定口径，
     * 但只给出结论、不提交任何状态。网关编排用它把“窗口内重复 / 序号回退 / 容量满”
     * 提前到配额占用之前判定——重复请求因此永远不会触碰限流配额，
     * 即使配额已满也稳定判 {@code REPLAYED_REQUEST}，不会被超限原因盖掉。
     * 预检通过后仍需以 {@link #check} 的原子复检+登记为准（预检不替代提交）。
     */
    public RejectionReason inspect(CallerPrincipal principal, GatewayRequest request) {
        RejectionReason stateless = checkStateless(principal.subjectId(), request);
        if (stateless != null) {
            return stateless;
        }
        SubjectState state = states.get(principal.subjectId());
        if (state == null) {
            return null;
        }
        long now = clock.millis();
        synchronized (state) {
            evictExpiredLogged(principal.subjectId(), state, now);
            return checkStatefulLocked(principal.subjectId(), state, request, now);
        }
    }

    /** 校验通过返回 null；否则返回可区分的拒绝原因。通过时原子登记 ID 并推进水位。 */
    public RejectionReason check(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();

        RejectionReason stateless = checkStateless(subject, request);
        if (stateless != null) {
            return stateless;
        }

        long now = clock.millis();
        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());

        synchronized (state) {
            // 1) 时效收敛：清理越过窗口的陈旧记录（expiry 基于请求自身时间戳 ts+skew）
            evictExpiredLogged(subject, state, now);

            // 2)~4) 查重 / 单调水位 / 容量上限
            RejectionReason reason = checkStatefulLocked(subject, state, request, now);
            if (reason != null) {
                return reason;
            }

            // 5) 通过：原子登记 + 推进水位（任何被拒路径都不会执行到这里）
            long ts = request.timestamp();
            long expiry = ts + properties.getTimestampSkewMillis();
            state.seenIds.put(request.requestId(), expiry);
            state.expiryQueue.addLast(new ExpiryEntry(expiry, request.requestId()));
            state.lastTimestamp = ts;
            if (request.sequence() != null) {
                state.lastSequence = request.sequence();
            }
            return null;
        }
    }

    /** 与状态无关的要素/时效检查：缺失要素、时间戳偏差。 */
    private RejectionReason checkStateless(String subject, GatewayRequest request) {
        if (request.requestId() == null || request.requestId().isBlank()) {
            return RejectionReason.MISSING_REQUEST_ID;
        }
        if (request.timestamp() == null) {
            return RejectionReason.MISSING_TIMESTAMP;
        }
        long now = clock.millis();
        long skew = properties.getTimestampSkewMillis();
        long ts = request.timestamp();
        if (ts < now - skew || ts > now + skew) {
            log.warn("时间窗口拒绝: subject={}, ts={}, now={}, skew={}", subject, ts, now, skew);
            return RejectionReason.TIMESTAMP_OUT_OF_WINDOW;
        }
        return null;
    }

    /** 依赖主体状态的检查（须在 state 锁内调用）：查重 -> 单调水位 -> 容量上限。 */
    private RejectionReason checkStatefulLocked(String subject, SubjectState state,
                                                GatewayRequest request, long now) {
        String requestId = request.requestId();
        long ts = request.timestamp();

        // 窗口内重放一律拦截（陈旧记录已在锁内移除，不会误伤窗口后的新请求）
        Long expiry = state.seenIds.get(requestId);
        if (expiry != null) {
            log.warn("重放拒绝: subject={}, requestId={}, expiresAt={}, now={}",
                    subject, requestId, expiry, now);
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

        // 容量收敛：过期记录已清完仍达上限 → 明确拒绝，不静默放过、不淘汰有效记录
        int max = properties.getReplayMaxIdsPerSubject();
        if (state.seenIds.size() >= max) {
            log.warn("重放容量拒绝: subject={}, retained={}, capacity={}, requestId={}",
                    subject, state.seenIds.size(), max, requestId);
            return RejectionReason.REPLAY_STORE_FULL;
        }
        return null;
    }

    private void evictExpiredLogged(String subject, SubjectState state, long now) {
        int evicted = state.evictExpired(now);
        if (evicted > 0) {
            log.info("重放记录时效清理: subject={}, evicted={}, retained={}",
                    subject, evicted, state.seenIds.size());
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
