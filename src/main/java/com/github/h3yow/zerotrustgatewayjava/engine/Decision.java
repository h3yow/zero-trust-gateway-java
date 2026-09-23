package com.github.h3yow.zerotrustgatewayjava.engine;

import com.github.h3yow.zerotrustgatewayjava.auth.RejectReason;

/**
 * 统一判定结论。allowed=false 时 reason 必非空，二者一一对应、可解释。
 *
 * @param allowed          是否放行
 * @param principal        归一化主体（凭证解析成功后有值）
 * @param keyId            请求携带的 keyId
 * @param reason           拒绝原因
 * @param detail           人类可读依据
 * @param rateLimitRemaining 剩余配额（经过限流阶段时有值）
 * @param rateLimitLimit     配额上限（经过限流阶段时有值）
 */
public record Decision(
        boolean allowed,
        String principal,
        String keyId,
        RejectReason reason,
        String detail,
        Long rateLimitRemaining,
        Long rateLimitLimit) {

    public static Decision allow(String principal, String keyId, long remaining, long limit) {
        return new Decision(true, principal, keyId, null, "request accepted", remaining, limit);
    }

    public static Decision reject(String principal, String keyId, RejectReason reason, String detail) {
        return new Decision(false, principal, keyId, reason, detail, null, null);
    }
}
