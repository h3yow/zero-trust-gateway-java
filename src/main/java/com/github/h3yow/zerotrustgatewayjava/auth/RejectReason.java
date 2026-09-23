package com.github.h3yow.zerotrustgatewayjava.auth;

/**
 * 可区分的拒绝原因。鉴权失败、限流、重放/篡改各占不同码段。
 */
public enum RejectReason {

    // ---- 凭证 / 鉴权类（401） ----
    MISSING_CREDENTIAL,
    UNKNOWN_KEY_ID,
    MALFORMED_CREDENTIAL,
    SIGNATURE_MISMATCH,
    CREDENTIAL_EXPIRED,
    PRINCIPAL_MISMATCH,
    BODY_TAMPERED,
    MALFORMED_REQUEST,

    // ---- 时间窗口 / 重放类（409） ----
    STALE_TIMESTAMP,
    NONCE_REPLAY,
    SEQUENCE_ROLLBACK,

    // ---- 限流类（429） ----
    RATE_LIMITED
}
