package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 统一调用主体：不同来源凭证校验通过后归一到该主体。
 */
public record CallerPrincipal(String subjectId, String credentialType, String credentialId) {
}
