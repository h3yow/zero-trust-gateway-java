package com.github.h3yow.zerotrustgatewayjava.ratelimit;

/**
 * 一次配额占用尝试的结果。
 *
 * @param allowed    是否放行
 * @param remaining  本窗口剩余额度（拒绝时为 0）
 * @param limit      窗口总额度
 * @param windowResetMs 距窗口重置的毫秒数
 */
public record RateLimitResult(boolean allowed, long remaining, long limit, long windowResetMs) {

    public static RateLimitResult rejected(long limit, long windowResetMs) {
        return new RateLimitResult(false, 0, limit, windowResetMs);
    }

    public static RateLimitResult accepted(long remaining, long limit, long windowResetMs) {
        return new RateLimitResult(true, remaining, limit, windowResetMs);
    }
}
