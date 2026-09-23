package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 凭证校验失败，携带可区分的拒绝原因。
 */
public class CredentialRejectedException extends RuntimeException {
    private final RejectionReason reason;

    public CredentialRejectedException(RejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectionReason getReason() {
        return reason;
    }
}
