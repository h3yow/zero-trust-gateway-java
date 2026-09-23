package com.github.h3yow.zerotrustgatewayjava.signature;

import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.credential.CredentialType;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/**
 * HMAC 签名/摘要校验。
 *
 * <p>无论凭证类型（V1/V2），都走同一套判定流程，区别仅在 HMAC 算法：
 * V1 为 HmacSHA1，V2 为 HmacSHA256。body 摘要统一为 SHA-256。
 *
 * <p>规范串（行分隔）：
 * <pre>
 * method
 * path
 * timestamp
 * nonce
 * sequence
 * bodySha256
 * </pre>
 */
@Component
public class HmacSignatureVerifier implements SignatureVerifier {

    private static final HexFormat HEX = HexFormat.of();

    @Override
    public boolean verify(RequestContext request, Credential credential) {
        if (request.signature() == null || request.bodyHash() == null) {
            return false;
        }
        String expectedBodyHash = bodyHash(request.body() == null ? new byte[0] : request.body());
        if (!constantTimeEquals(expectedBodyHash, request.bodyHash())) {
            // 摘要不符 = 防篡改失败
            return false;
        }
        String expectedSignature = sign(request, credential);
        return constantTimeEquals(expectedSignature, request.signature());
    }

    @Override
    public String canonicalString(RequestContext request) {
        return String.join("\n",
                nullSafe(request.method()),
                nullSafe(request.path()),
                request.timestamp() == null ? "" : request.timestamp().toString(),
                nullSafe(request.nonce()),
                request.sequence() == null ? "" : request.sequence().toString(),
                nullSafe(request.bodyHash()));
    }

    @Override
    public String sign(RequestContext request, Credential credential) {
        String algorithm = credential.type() == CredentialType.V1_HMAC_SHA1 ? "HmacSHA1" : "HmacSHA256";
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(credential.secret().getBytes(StandardCharsets.UTF_8), algorithm));
            byte[] raw = mac.doFinal(canonicalString(request).getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(raw);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC computation failed: " + algorithm, e);
        }
    }

    @Override
    public String bodyHash(byte[] body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HEX.formatHex(digest.digest(body == null ? new byte[0] : body));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 computation failed", e);
        }
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    /** 定长十六进制串的常量时间比较，避免签名比对侧信道。 */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(x, y);
    }
}
