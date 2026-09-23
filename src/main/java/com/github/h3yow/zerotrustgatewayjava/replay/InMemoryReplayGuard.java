package com.github.h3yow.zerotrustgatewayjava.replay;

import com.github.h3yow.zerotrustgatewayjava.config.GatewayProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 纯内存防重放/防序号回退。
 *
 * <p>以主体为维度保存：
 * <ul>
 *   <li>最近接受的序号 latestSequence（请求必须严格递增）；</li>
 *   <li>有效期内已使用 nonce 的过期时间戳（默认 TTL 内重复即拒绝）。</li>
 * </ul>
 *
 * <p>提交在 {@link ConcurrentHashMap#compute} 内原子完成，
 * 同一 nonce 并发提交恰好只有一次 ACCEPTED，不会因竞态静默通过。
 * 过期 nonce 在该主体下一次提交时惰性清理，内存占用受 TTL 约束。
 */
@Component
public class InMemoryReplayGuard implements ReplayGuard {

    private final long nonceTtlMillis;
    private final Map<String, PrincipalState> states = new ConcurrentHashMap<>();

    public InMemoryReplayGuard(GatewayProperties properties) {
        this.nonceTtlMillis = properties.nonceTtlSeconds() * 1000L;
    }

    @Override
    public ReplayResult commit(String principal, String nonce, long sequence, long nowMillis) {
        final ReplayResult[] outcome = new ReplayResult[1];
        states.compute(principal, (key, existing) -> {
            PrincipalState state = existing == null ? new PrincipalState() : existing;

            // 惰性清理过期 nonce
            state.nonceExpiries.values().removeIf(expiry -> expiry <= nowMillis);

            Long expiry = state.nonceExpiries.get(nonce);
            if (expiry != null && expiry > nowMillis) {
                outcome[0] = ReplayResult.DUPLICATE_NONCE;
                return state;
            }

            if (sequence <= state.latestSequence) {
                outcome[0] = ReplayResult.SEQUENCE_ROLLBACK;
                return state;
            }

            state.nonceExpiries.put(nonce, nowMillis + nonceTtlMillis);
            state.latestSequence = sequence;
            outcome[0] = ReplayResult.ACCEPTED;
            return state;
        });
        return outcome[0];
    }

    /** 单主体的重放状态。仅在 ConcurrentHashMap.compute 内访问。 */
    private static final class PrincipalState {
        private long latestSequence = Long.MIN_VALUE;
        private final Map<String, Long> nonceExpiries = new HashMap<>();
    }
}
