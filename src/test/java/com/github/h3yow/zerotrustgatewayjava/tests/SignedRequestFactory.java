package com.github.h3yow.zerotrustgatewayjava.tests;

import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.HmacCredentialVerifier;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 测试用：按 HMAC1/HMAC2 规则构造已签名的 {@link GatewayRequest}。
 * 密钥取自本地配置的同一组测试材料，不涉及任何真实凭证。
 */
final class SignedRequestFactory {

    private SignedRequestFactory() {
    }

    static String bodySha256(String body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                    digest.digest((body == null ? "" : body).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * @param version       HMAC1（hex 签名）或 HMAC2（base64 签名）
     * @param subject       凭证内嵌主体（keyId/subject 字段），签名原文也绑定它
     * @param signAsSubject 实际用于签名的主体密钥；为 null 时用 subject 自身密钥。
     *                      传入其他主体即可构造“用错密钥”的签名。
     */
    static GatewayRequest signed(LocalCredentialRegistry registry, String version, String subject,
                                 String claimedSubject, String requestId, long timestamp, Long sequence,
                                 String method, String path, String bodySha, long expiresAt,
                                 String signAsSubject) {
        GatewayRequest unsigned = new GatewayRequest(
                null, claimedSubject, requestId, timestamp, sequence, method, path, bodySha);
        String keySubject = signAsSubject == null ? subject : signAsSubject;
        String encoding = "HMAC2".equals(version) ? "base64" : "hex";
        String canonical = HmacCredentialVerifier.canonical(version, unsigned, subject, expiresAt);
        String sig = registry.sign(keySubject, canonical, encoding);
        String header = version + " keyId=" + subject + ";subject=" + subject
                + ";expires=" + expiresAt + ";sig=" + sig;
        return new GatewayRequest(header, claimedSubject, requestId, timestamp, sequence,
                method, path, bodySha);
    }

    static GatewayRequest signed(LocalCredentialRegistry registry, String version, String subject,
                                 String claimedSubject, String requestId, long timestamp, Long sequence,
                                 String method, String path, String bodySha) {
        return signed(registry, version, subject, claimedSubject, requestId, timestamp, sequence,
                method, path, bodySha, System.currentTimeMillis() + 600_000, null);
    }

    static GatewayRequest signed(LocalCredentialRegistry registry, String version, String subject,
                                 String requestId, long timestamp, Long sequence,
                                 String method, String path, String bodySha) {
        return signed(registry, version, subject, subject, requestId, timestamp, sequence,
                method, path, bodySha, System.currentTimeMillis() + 600_000, null);
    }

    /** 用给定签名原文要素重算后，替换成伪造签名（制造 SIGNATURE_MISMATCH）。 */
    static GatewayRequest withForgedSignature(GatewayRequest original) {
        String header = original.credentialHeader().replaceAll("sig=[^;]+", "sig=deadbeef");
        return new GatewayRequest(header, original.claimedSubject(), original.requestId(),
                original.timestamp(), original.sequence(), original.method(), original.path(),
                original.bodySha256());
    }
}
