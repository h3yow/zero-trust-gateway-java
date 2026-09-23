package com.github.h3yow.zerotrustgatewayjava.credential;

import java.time.Instant;

/**
 * 一份本地登记的调用方凭证。
 *
 * @param keyId      公钥标识（请求头 X-ZT-Key-Id）
 * @param secret     共享密钥（仅本地配置）
 * @param type       凭证类型/版本
 * @param principal  归一化后的统一调用主体
 * @param expiresAt  凭证失效时间
 */
public record Credential(
        String keyId,
        String secret,
        CredentialType type,
        String principal,
        Instant expiresAt) {
}
