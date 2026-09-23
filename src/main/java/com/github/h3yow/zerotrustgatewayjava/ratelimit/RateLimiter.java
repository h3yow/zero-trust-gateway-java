package com.github.h3yow.zerotrustgatewayjava.ratelimit;

/**
 * 以调用主体为维度的本地限流。
 * 实现必须保证并发下不超发、不丢计数；额度可通过 release 归还，避免被永久占用。
 */
public interface RateLimiter {

    /** 尝试占用一个额度。 */
    RateLimitResult tryAcquire(String principal);

    /** 归还一个此前成功占用的额度（请求最终未被放行时调用）。 */
    void release(String principal);
}
