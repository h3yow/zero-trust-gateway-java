package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 网关需要的请求要素（从 HTTP 头中提取）。
 */
public record GatewayRequest(
        String credentialHeader,
        String claimedSubject,
        String requestId,
        Long timestamp,
        Long sequence,
        String method,
        String path,
        String bodySha256
) {
}
