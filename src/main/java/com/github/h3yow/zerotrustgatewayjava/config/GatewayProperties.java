package com.github.h3yow.zerotrustgatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Instant;
import java.util.List;

/**
 * 本地可调参数与凭证登记，全部来自 application.properties，无外部依赖。
 */
@ConfigurationProperties(prefix = "ztg")
public record GatewayProperties(
        Long timestampWindowSeconds,
        Long nonceTtlSeconds,
        Long rateLimitRequests,
        Long rateLimitWindowSeconds,
        List<CredentialConfig> credentials) {

    public record CredentialConfig(
            String keyId,
            String secret,
            String type,
            String principal,
            Instant expiresAt) {
    }
}
