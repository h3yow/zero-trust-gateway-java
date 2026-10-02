package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 以调用主体为维度的本地固定窗口限流器。
 *
 * <p>并发语义（每主体独立锁，锁内完成“窗口判定 + 计数”）：
 * <ul>
 *   <li>窗口内成功放行量绝不超过 {@code quotaPerWindow}，不存在 CAS 竞态丢失计数；</li>
 *   <li>被拒绝的请求不增加计数，额度不会被超限请求永久占用；</li>
 *   <li>{@link #release} 用于“先占额后判定”的编排：占用后若后续判定（防重放等）
 *       未真正放行，则原样退还额度，最终语义仍是只有真正处理的请求计费；</li>
 *   <li>窗口过期后计数清零滚动，配额自动恢复。</li>
 * </ul>
 */
@Component
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    private final GatewayProperties properties;
    private final GatewayClock clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimiter(GatewayProperties properties, GatewayClock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** 尝试占用一个配额；返回 false 表示超限，且本次拒绝不消耗额度。 */
    public boolean tryAcquire(String subjectId) {
        Window window = windows.computeIfAbsent(subjectId, k -> new Window(clock.nowMillis()));
        synchronized (window) {
            if (clock.nowMillis() - window.start >= properties.getWindowMillis()) {
                // 窗口滚动：旧计数作废，配额恢复
                window.start = clock.nowMillis();
                window.count = 0;
            }
            if (window.count >= properties.getQuotaPerWindow()) {
                log.warn("限流拒绝: subject={}, used={}, quota={}",
                        subjectId, window.count, properties.getQuotaPerWindow());
                return false;
            }
            window.count++;
            return true;
        }
    }

    /**
     * 退还一个先前占用但最终未真正处理的配额。
     * 若占用发生在更早的已滚动窗口，则本次退还无意义（直接忽略，不影响新窗口）。
     */
    public void release(String subjectId) {
        Window window = windows.get(subjectId);
        if (window == null) {
            return;
        }
        synchronized (window) {
            if (clock.nowMillis() - window.start >= properties.getWindowMillis()) {
                return;
            }
            if (window.count > 0) {
                window.count--;
            }
        }
    }

    /** 仅供测试：清空计数。 */
    public void reset() {
        windows.clear();
    }

    private static final class Window {
        private long start;
        private long count;

        Window(long start) {
            this.start = start;
        }
    }
}
