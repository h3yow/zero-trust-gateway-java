package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 本地凭证注册表：启动时从配置解析 subjectId -> base64 密钥，全部状态在本地内存，
 * 不依赖任何外部服务或真实凭证。
 *
 * <p>配置格式（逗号分隔多条）：
 * <pre>zero-trust.gateway.credentials=alice:BASE64KEY,bob:BASE64KEY</pre>
 */
@Component
public class LocalCredentialRegistry {

    private final java.util.Map<String, byte[]> keys = new java.util.HashMap<>();

    public LocalCredentialRegistry(GatewayProperties properties) {
        String raw = properties.getCredentials();
        if (StringUtils.hasText(raw)) {
            for (String entry : raw.split(",")) {
                String item = entry.trim();
                if (item.isEmpty()) {
                    continue;
                }
                int idx = item.indexOf(':');
                if (idx <= 0) {
                    throw new IllegalArgumentException("非法凭证配置: " + item);
                }
                String subject = item.substring(0, idx).trim();
                byte[] key = Base64.getDecoder().decode(item.substring(idx + 1).trim());
                keys.put(subject, key);
            }
        }
    }

    /** 该主体是否存在本地密钥。 */
    public boolean knows(String subjectId) {
        return keys.containsKey(subjectId);
    }

    /**
     * 验签：对 canonical 字符串做 HmacSHA256，常量时间比较。
     * @param encoding "hex"（HMAC1/v1）或 "base64"（HMAC2/v2）
     */
    public boolean verifySignature(String subjectId, String canonical, String providedSig, String encoding) {
        byte[] key = keys.get(subjectId);
        if (key == null) {
            return false;
        }
        String expected = encode(hmac(key, canonical), encoding);
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                providedSig == null ? new byte[0] : providedSig.trim().getBytes(StandardCharsets.UTF_8));
    }

    /** 仅供本地/测试签名使用。 */
    public String sign(String subjectId, String canonical, String encoding) {
        byte[] key = keys.get(subjectId);
        if (key == null) {
            throw new IllegalArgumentException("未知主体: " + subjectId);
        }
        return encode(hmac(key, canonical), encoding);
    }

    private static byte[] hmac(byte[] key, String canonical) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }

    private static String encode(byte[] raw, String encoding) {
        if ("hex".equalsIgnoreCase(encoding)) {
            StringBuilder sb = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        }
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.getEncoder().encodeToString(raw);
        }
        throw new IllegalArgumentException("不支持的签名编码: " + encoding);
    }
}
