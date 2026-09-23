package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * HMAC 凭证校验器，同一套判定流程兼容两个版本：
 * <ul>
 *   <li><b>HMAC1</b>（v1）：签名编码为 HmacSHA256 的小写 hex；</li>
 *   <li><b>HMAC2</b>（v2）：签名编码为 HmacSHA256 的 base64。</li>
 * </ul>
 *
 * 凭证头形如：
 * <pre>HMAC1 keyId=alice;subject=alice;expires=1790000000000;sig=....</pre>
 * 签名覆盖完整请求要素（方法、路径、请求 ID、时间戳、序号、正文摘要），因此凭证也承担防篡改绑定。
 */
@Component
public class HmacCredentialVerifier implements CredentialVerifier {

    private static final Logger log = LoggerFactory.getLogger(HmacCredentialVerifier.class);

    static final String VERSION_1 = "HMAC1";
    static final String VERSION_2 = "HMAC2";

    private final LocalCredentialRegistry registry;

    public HmacCredentialVerifier(LocalCredentialRegistry registry) {
        this.registry = registry;
    }

    @Override
    public boolean supports(String credentialHeader) {
        if (credentialHeader == null) {
            return false;
        }
        String h = credentialHeader.trim();
        return h.startsWith(VERSION_1 + " ") || h.startsWith(VERSION_2 + " ");
    }

    @Override
    public CallerPrincipal verify(GatewayRequest request) {
        String header = request.credentialHeader().trim();
        String version = header.startsWith(VERSION_2 + " ") ? VERSION_2 : VERSION_1;
        String encoding = version.equals(VERSION_2) ? "base64" : "hex";
        String paramsPart = header.substring(version.length()).trim();

        Map<String, String> params = parseParams(paramsPart);
        String keyId = params.get("keyId");
        String subject = params.get("subject");
        String expiresRaw = params.get("expires");
        String sig = params.get("sig");

        if (isBlank(keyId) || isBlank(subject) || isBlank(expiresRaw) || isBlank(sig)) {
            throw reject(RejectionReason.MALFORMED_CREDENTIAL,
                    version + " 凭证缺少必填字段(keyId/subject/expires/sig): " + paramsPart);
        }

        long expires;
        try {
            expires = Long.parseLong(expiresRaw.trim());
        } catch (NumberFormatException e) {
            throw reject(RejectionReason.MALFORMED_CREDENTIAL,
                    version + " 凭证 expires 不是毫秒时间戳: " + expiresRaw);
        }

        // 主体一致性：请求显式声明的主体必须与凭证内嵌主体一致
        if (!isBlank(request.claimedSubject()) && !request.claimedSubject().trim().equals(subject.trim())) {
            throw reject(RejectionReason.PRINCIPAL_MISMATCH,
                    "声明主体 " + request.claimedSubject() + " 与凭证主体 " + subject + " 不一致");
        }

        String subjectId = subject.trim();
        if (!registry.knows(subjectId) || !keyId.trim().equals(subjectId)) {
            throw reject(RejectionReason.SIGNATURE_MISMATCH,
                    version + " 凭证 keyId/主体未在本地登记: keyId=" + keyId + ", subject=" + subject);
        }

        if (System.currentTimeMillis() > expires) {
            throw reject(RejectionReason.CREDENTIAL_EXPIRED,
                    version + " 凭证已于 " + expires + " 过期");
        }

        String canonical = canonical(version, request, subjectId, expires);
        if (!registry.verifySignature(subjectId, canonical, sig, encoding)) {
            throw reject(RejectionReason.SIGNATURE_MISMATCH,
                    version + " 签名与重算结果不符（可能密钥错误或请求被篡改）");
        }

        log.debug("凭证校验通过: version={}, subject={}", version, subjectId);
        return new CallerPrincipal(subjectId, version, keyId.trim());
    }

    /**
     * 构造签名原文：版本 + 凭证字段 + 全部请求绑定要素，逐行以 '\n' 连接。
     */
    public static String canonical(String version, GatewayRequest request, String subject, long expires) {
        return String.join("\n",
                version,
                subject,
                subject,
                Long.toString(expires),
                nz(request.method()),
                nz(request.path()),
                nz(request.requestId()),
                request.timestamp() == null ? "" : Long.toString(request.timestamp()),
                request.sequence() == null ? "" : Long.toString(request.sequence()),
                nz(request.bodySha256()));
    }

    private static Map<String, String> parseParams(String paramsPart) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : paramsPart.split(";")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                params.put(pair.substring(0, idx).trim(), pair.substring(idx + 1).trim());
            }
        }
        return params;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private CredentialRejectedException reject(RejectionReason reason, String message) {
        log.warn("凭证拒绝: reason={}, detail={}", reason, message);
        return new CredentialRejectedException(reason, message);
    }
}
