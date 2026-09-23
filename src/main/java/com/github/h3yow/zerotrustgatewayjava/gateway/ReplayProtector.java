package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.Map;
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
 *   <li>同一主体的 requestId 在有效期内只能使用一次，重复提交（含并发重放）→
 *       {@code REPLAYED_REQUEST}；</li>
 *   <li>(timestamp, sequence) 必须严格单调递增，时间或序号回退 →
 *       {@code SEQUENCE_REGRESSION}。</li>
 * </ol>
 *
 * <p>每个主体独立加锁，“查重 + 登记”在同一临界区原子完成，杜绝并发重放双放行。
 * 只有通过全部检查的请求才会登记 ID 并推进水位，被拒请求不会污染状态，判定结果稳定可复现。
 */
@Component
public class ReplayProtector {

    private static final Logger log = LoggerFactory.getLogger(ReplayProtector.class);

    /** 单主体已记录 ID 数量超过该阈值时顺带清理过期条目，避免内存无界增长。 */
    private static final int CLEANUP_THRESHOLD = 4096;

    private final GatewayProperties properties;
    private final ConcurrentHashMap<String, SubjectState> states = new ConcurrentHashMap<>();

    public ReplayProtector(GatewayProperties properties) {
        this.properties = properties;
    }

    /** 校验通过返回 null；否则返回可区分的拒绝原因。 */
    public RejectionReason check(CallerPrincipal principal, GatewayRequest request) {
        String subject = principal.subjectId();

        if (request.requestId() == null || request.requestId().isBlank()) {
            return RejectionReason.MISSING_REQUEST_ID;
        }
        if (request.timestamp() == null) {
            return RejectionReason.MISSING_TIMESTAMP;
        }

        long now = System.currentTimeMillis();
        long skew = properties.getTimestampSkewMillis();
        long ts = request.timestamp();
        if (ts < now - skew || ts > now + skew) {
            log.warn("时间窗口拒绝: subject={}, ts={}, now={}, skew={}", subject, ts, now, skew);
            return RejectionReason.TIMESTAMP_OUT_OF_WINDOW;
        }

        SubjectState state = states.computeIfAbsent(subject, k -> new SubjectState());
        String requestId = request.requestId();
        long expiry = now + skew;

        synchronized (state) {
            // 清理过期 ID（顺带，不改变本次判定语义）
            if (state.seenIds.size() > CLEANUP_THRESHOLD) {
                state.seenIds.entrySet().removeIf(e -> e.getValue() < now);
            }

            if (state.seenIds.containsKey(requestId)) {
                log.warn("重放拒绝: subject={}, requestId={}", subject, requestId);
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

            // 通过：原子登记 + 推进水位（被拒路径不会执行到这里）
            state.seenIds.put(requestId, expiry);
            state.lastTimestamp = ts;
            if (request.sequence() != null) {
                state.lastSequence = request.sequence();
            }
            return null;
        }
    }

    /** 仅供测试：清空状态。 */
    public void reset() {
        states.clear();
    }

    private static final class SubjectState {
        /** requestId -> 过期时间（epochMillis）。 */
        private final Map<String, Long> seenIds = new ConcurrentHashMap<>();
        private long lastTimestamp = Long.MIN_VALUE;
        private Long lastSequence;
    }
}
