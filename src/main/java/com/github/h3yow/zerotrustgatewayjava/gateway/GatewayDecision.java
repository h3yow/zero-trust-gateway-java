package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 判定结果：allowed=false 时 reason 必填且可解释。
 */
public record GatewayDecision(
        boolean allowed,
        RejectionReason reason,
        String message,
        CallerPrincipal principal
) {
    public static GatewayDecision allow(CallerPrincipal principal) {
        return new GatewayDecision(true, null, "allowed", principal);
    }

    public static GatewayDecision reject(RejectionReason reason, String message) {
        return new GatewayDecision(false, reason, message, null);
    }
}
