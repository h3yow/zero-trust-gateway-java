package com.github.h3yow.zerotrustgatewayjava.credential;

import com.github.h3yow.zerotrustgatewayjava.config.GatewayProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 基于 application.properties 的本地凭证库。启动时一次性构建不可变索引。
 */
@Component
public class LocalCredentialStore implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(LocalCredentialStore.class);

    private final Map<String, Credential> byKeyId;

    public LocalCredentialStore(GatewayProperties properties) {
        this.byKeyId = properties.credentials() == null ? Map.of() : properties.credentials().stream()
                .map(LocalCredentialStore::toCredential)
                .collect(Collectors.toUnmodifiableMap(Credential::keyId, Function.identity()));
        log.info("Local credential store loaded {} credential(s): {}", byKeyId.size(), byKeyId.keySet());
    }

    @Override
    public Optional<Credential> find(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byKeyId.get(keyId));
    }

    private static Credential toCredential(GatewayProperties.CredentialConfig config) {
        return new Credential(
                config.keyId(),
                config.secret(),
                CredentialType.valueOf(config.type()),
                config.principal(),
                config.expiresAt());
    }
}
