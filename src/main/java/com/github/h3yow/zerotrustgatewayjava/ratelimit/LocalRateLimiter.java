package com.github.h3yow.zerotrustgatewayjava.ratelimit;

import com.github.h3yow.zerotrustgatewayjava.config.GatewayProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按调用主体维度的固定窗口限流器（纯内存、线程安全）。
 *
 * <p>并发安全保证：所有计数变更在每个主体的 Window 实例监视器内完成
 * （{@link ConcurrentHashMap#compute}），因此高并发下：
 * <ul>
 *   <li>不会计数丢失；</li>
 *   <li>实际放行量绝不超过配额；</li>
 *   <li>{@link #release(String)} 归还额度，避免请求在后续阶段被拒时额度被永久占用。</li>
 * </ul>
 */
@Component
public class LocalRateLimiter implements RateLimiter {

    private final long limit;
    private final long windowMillis;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public LocalRateLimiter(GatewayProperties properties, Clock clock) {
        this.limit = properties.rateLimitRequests();
        this.windowMillis = properties.rateLimitWindowSeconds() * 1000L;
        this.clock = clock;
    }

    @Override
    public RateLimitResult tryAcquire(String principal) {
        long now = clock.millis();
        final RateLimitResult[] outcome = new RateLimitResult[1];
        windows.compute(principal, (key, window) -> {
            Window current = window;
            if (current == null || now - current.windowStart >= windowMillis) {
                current = new Window(now);
            }
            long resetMs = current.windowStart + windowMillis - now;
            if (current.count < limit) {
                current.count++;
                outcome[0] = RateLimitResult.accepted(limit - current.count, limit, resetMs);
            } else {
                outcome[0] = RateLimitResult.rejected(limit, Math.max(resetMs, 0));
            }
            return current;
        });
        return outcome[0];
    }

    @Override
    public void release(String principal) {
        long now = clock.millis();
        windows.computeIfPresent(principal, (key, window) -> {
            // 窗口已滚动则不触碰新窗口的计数；本次占用随旧窗口一起过期
            if (now - window.windowStart >= windowMillis) {
                return window;
            }
            if (window.count > 0) {
                window.count--;
            }
            return window;
        });
    }

    /** 单主体的固定窗口状态。仅在自身监视器内被访问（compute 保证）。 */
    private static final class Window {
        private final long windowStart;
        private long count;

        private Window(long windowStart) {
            this.windowStart = windowStart;
            this.count = 0;
        }
    }
}
