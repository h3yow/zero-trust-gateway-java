package com.github.h3yow.zerotrustgatewayjava.replay;

/**
 * 防重放/防回退：以主体为维度记录已用 nonce 与最新序号。
 * 提交必须是原子操作，保证同一 nonce 并发提交只有一个成功。
 */
public interface ReplayGuard {

    /**
     * 原子提交。
     *
     * @param principal 调用主体
     * @param nonce     请求唯一标识
     * @param sequence  单调递增序号
     * @param nowMillis 当前时间（毫秒）
     */
    ReplayResult commit(String principal, String nonce, long sequence, long nowMillis);
}
