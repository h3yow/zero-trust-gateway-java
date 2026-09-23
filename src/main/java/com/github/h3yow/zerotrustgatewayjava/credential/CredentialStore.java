package com.github.h3yow.zerotrustgatewayjava.credential;

import java.util.Optional;

/**
 * 凭证库：按 keyId 解析本地登记凭证。
 */
public interface CredentialStore {
    Optional<Credential> find(String keyId);
}
