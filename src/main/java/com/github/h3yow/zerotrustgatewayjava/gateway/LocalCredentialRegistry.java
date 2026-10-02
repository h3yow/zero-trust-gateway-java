package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 本地凭证注册表：启动时从配置解析 subjectId -> (密钥, 生命周期)，全部状态在本地内存，
 * 不依赖任何外部服务或真实凭证。
 *
 * <p>配置格式（逗号分隔多条）：
 * <pre>
 * zero-trust.gateway.credentials=alice:BASE64KEY,bob:BASE64KEY
 * # 可选生命周期段（冒号分段，均可选）：subjectId:base64(notBefore:notAfter:revoked)
 * zero-trust.gateway.credentials=alice:BASE64KEY:1700000000000:1800000000000:false
 * </pre>
 * 其中 {@code notBefore}/{@code notAfter} 为 epoch 毫秒，留空表示不设限；
 * {@code revoked} 为 {@code true}/{@code false}（默认 false）。
 * 不带生命周期段的旧格式仍然合法，表示“已登记、无时间限制”，向后兼容。
 *
 * <p>运行期可随时通过 {@link #revoke(String)} 撤销、{@link #register} 重新登记；
 * 判定一律以本地登记的生命周期为准，客户端凭证头自带的时间或状态不能覆盖本地结论。
 */
@Component
public class LocalCredentialRegistry {

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();

    public LocalCredentialRegistry(GatewayProperties properties) {
        String raw = properties.getCredentials();
        if (StringUtils.hasText(raw)) {
            for (String entry : raw.split(",")) {
                String item = entry.trim();
                if (item.isEmpty()) {
                    continue;
                }
                String[] parts = item.split(":", 5);
                if (parts.length < 2 || parts[0].trim().isEmpty()) {
                    throw new IllegalArgumentException("非法凭证配置: " + item);
                }
                String subject = parts[0].trim();
                byte[] key = Base64.getDecoder().decode(parts[1].trim());
                CredentialLifecycle lifecycle;
                if (parts.length <= 2) {
                    lifecycle = CredentialLifecycle.active();
                } else {
                    Long notBefore = parseEpoch(parts, 2, item);
                    Long notAfter = parseEpoch(parts, 3, item);
                    boolean revoked = parts.length >= 5 && "true".equalsIgnoreCase(parts[4].trim());
                    lifecycle = new CredentialLifecycle(notBefore, notAfter, revoked);
                }
                entries.put(subject, new Entry(key, lifecycle));
            }
        }
    }

    private static Long parseEpoch(String[] parts, int idx, String raw) {
        if (parts.length <= idx) {
            return null;
        }
        String v = parts[idx].trim();
        if (v.isEmpty()) {
            return null;
        }
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("凭证生命周期时间不是毫秒时间戳: " + raw, e);
        }
    }

    /** 该主体是否存在本地登记（含已撤销的登记；撤销由生命周期判定另行处理）。 */
    public boolean knows(String subjectId) {
        return entries.containsKey(subjectId);
    }

    /** 本地登记的生命周期；未登记返回 {@code null}。 */
    public CredentialLifecycle lifecycleOf(String subjectId) {
        Entry e = entries.get(subjectId);
        return e == null ? null : e.lifecycle;
    }

    /** 登记/覆盖一个主体的密钥与生命周期（可用于撤销后重新发放）。 */
    public void register(String subjectId, byte[] key, CredentialLifecycle lifecycle) {
        entries.put(subjectId, new Entry(key, lifecycle == null ? CredentialLifecycle.active() : lifecycle));
    }

    /** 立即撤销该主体的凭证；返回 false 表示该主体未在本地登记，无法撤销。 */
    public boolean revoke(String subjectId) {
        Entry e = entries.get(subjectId);
        if (e == null) {
            return false;
        }
        e.lifecycle = e.lifecycle.asRevoked();
        return true;
    }

    /**
     * 验签：对 canonical 字符串做 HmacSHA256，常量时间比较。
     * @param encoding "hex"（HMAC1/v1）或 "base64"（HMAC2/v2）
     */
    public boolean verifySignature(String subjectId, String canonical, String providedSig, String encoding) {
        Entry e = entries.get(subjectId);
        if (e == null) {
            return false;
        }
        String expected = encode(hmac(e.key, canonical), encoding);
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                providedSig == null ? new byte[0] : providedSig.trim().getBytes(StandardCharsets.UTF_8));
    }

    /** 仅供本地/测试签名使用。 */
    public String sign(String subjectId, String canonical, String encoding) {
        Entry e = entries.get(subjectId);
        if (e == null) {
            throw new IllegalArgumentException("未知主体: " + subjectId);
        }
        return encode(hmac(e.key, canonical), encoding);
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

    /** 可变生命周期（支持原地撤销），密钥不可变。 */
    private static final class Entry {
        private final byte[] key;
        private volatile CredentialLifecycle lifecycle;

        private Entry(byte[] key, CredentialLifecycle lifecycle) {
            this.key = key;
            this.lifecycle = lifecycle;
        }
    }
}
