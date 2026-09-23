package com.github.h3yow.zerotrustgatewayjava.tests.security;

import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.credential.CredentialType;
import com.github.h3yow.zerotrustgatewayjava.signature.HmacSignatureVerifier;
import com.github.h3yow.zerotrustgatewayjava.signature.SignatureVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 签名/摘要规则单元测试：V1(HMAC-SHA1) 与 V2(HMAC-SHA256) 同流程、可互证。
 */
class SignatureVerifierTest {

    private static final Logger log = LoggerFactory.getLogger(SignatureVerifierTest.class);

    private final SignatureVerifier verifier = new HmacSignatureVerifier();

    private final Credential v1 = new Credential("k1", "secret-v1",
            CredentialType.V1_HMAC_SHA1, "svc-a", Instant.parse("2099-01-01T00:00:00Z"));
    private final Credential v2 = new Credential("k2", "secret-v2",
            CredentialType.V2_HMAC_SHA256, "svc-a", Instant.parse("2099-01-01T00:00:00Z"));

    private RequestContext base(byte[] body, String bodyHash, String signature) {
        return new RequestContext("POST", "/api/echo", body, "k", "svc-a",
                1_700_000_000L, "nonce", 1L, bodyHash, signature);
    }

    @Test
    @DisplayName("V1 与 V2 签名都能按同一 verify 流程验签通过")
    void bothVersionsVerify() {
        for (Credential c : new Credential[]{v1, v2}) {
            byte[] body = "payload".getBytes();
            String hash = verifier.bodyHash(body);
            String sig = verifier.sign(base(body, hash, null), c);
            boolean ok = verifier.verify(base(body, hash, sig), c);
            log.info("credential type={} signature={} verify={}", c.type(), sig, ok);
            assertThat(ok).isTrue();
            // V1 为 40 位 SHA1 hex，V2 为 64 位 SHA256 hex
            assertThat(sig).hasSize(c.type() == CredentialType.V1_HMAC_SHA1 ? 40 : 64);
        }
    }

    @Test
    @DisplayName("V1/V2 对同一规范串产生不同签名（算法不同）")
    void algorithmsProduceDifferentSignatures() {
        byte[] body = "payload".getBytes();
        String hash = verifier.bodyHash(body);
        RequestContext ctx = base(body, hash, null);
        assertThat(verifier.sign(ctx, v1)).isNotEqualTo(verifier.sign(ctx, v2));
    }

    @Test
    @DisplayName("body 一改，原签名即失效")
    void changedBodyFailsVerification() {
        byte[] body = "payload".getBytes();
        String hash = verifier.bodyHash(body);
        String sig = verifier.sign(base(body, hash, null), v2);

        assertThat(verifier.verify(base("PAYLOAD".getBytes(), hash, sig), v2)).isFalse();
    }

    @Test
    @DisplayName("用 A 密钥签名不能通过 B 凭证验签")
    void wrongSecretFails() {
        byte[] body = "payload".getBytes();
        String hash = verifier.bodyHash(body);
        String sigByV1 = verifier.sign(base(body, hash, null), v1);
        // 签名头是 v1 密钥算的，却用 v2 凭证验
        assertThat(verifier.verify(base(body, hash, sigByV1), v2)).isFalse();
    }

    @Test
    @DisplayName("空 body 也有确定摘要，同输入结果稳定")
    void emptyBodyDeterministic() {
        String h1 = verifier.bodyHash(new byte[0]);
        String h2 = verifier.bodyHash(new byte[0]);
        assertThat(h1).isEqualTo(h2).isEqualTo(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
