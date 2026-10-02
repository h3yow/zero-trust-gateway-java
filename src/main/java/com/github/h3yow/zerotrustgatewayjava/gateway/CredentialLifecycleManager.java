package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * 服务端集中管理的凭证生命周期：登记每个调用主体的生效时间（notBefore）、
 * 失效时间（notAfter）与撤销状态（revoked）。
 *
 * <p>判定一律以<b>本地登记</b>为准：哪怕客户端凭证头里的 {@code expires} 看起来仍有效，
 * 只要本地登记显示未生效 / 已失效 / 已撤销，就拒绝。两类凭证版本（HMAC1/HMAC2）
 * 归一到同一 subjectId 后走同一套判定，且与“签名不符 / 主体不一致”原因明确区分。
 *
 * <p>配置格式（{@code zero-trust.gateway.credential-lifecycles}，逗号分隔）：
 * <pre>
 * charlie:1759400000000:1790000000000   # 仅在 [notBefore, notAfter] 内有效
 * dave::1759000000000                   # notBefore 留空，仅设失效时间
 * erin:revoked                          # 立即撤销
 * </pre>
 * 未登记生命周期的主体不受此约束（与旧配置完全兼容）；撤销也可在运行时通过
 * {@link #revoke(String)} 立即执行。
 */
@Component
public class CredentialLifecycleManager {

    private static final Logger log = LoggerFactory.getLogger(CredentialLifecycleManager.class);

    private final String rawConfig;
    private final Map<String, Lifecycle> configured = new HashMap<>();
    private final ConcurrentHashMap<String, Lifecycle> overrides = new ConcurrentHashMap<>();

    public CredentialLifecycleManager(GatewayProperties properties) {
        this.rawConfig = properties.getCredentialLifecycles();
        this.configured.putAll(parse(rawConfig));
        log.info("凭证生命周期登记完成: {}", this.configured);
    }

    /**
     * 按本地登记判定主体生命周期；任一项不满足即抛出可区分原因：
     * 撤销 → {@code CREDENTIAL_REVOKED}；未到生效时间 → {@code CREDENTIAL_NOT_YET_VALID}；
     * 超过失效时间 → {@code CREDENTIAL_EXPIRED}。未登记则直接放行。
     */
    public void enforce(String subjectId, long nowMillis) {
        Lifecycle lc = current(subjectId);
        if (lc == null) {
            return;
        }
        if (lc.revoked()) {
            log.warn("生命周期拒绝: subject={}, 本地登记状态=已撤销", subjectId);
            throw new CredentialRejectedException(RejectionReason.CREDENTIAL_REVOKED,
                    "主体 " + subjectId + " 的凭证已被服务端本地登记撤销");
        }
        if (lc.notBefore() != null && nowMillis < lc.notBefore()) {
            log.warn("生命周期拒绝: subject={}, now={}, notBefore={} 本地登记尚未生效",
                    subjectId, nowMillis, lc.notBefore());
            throw new CredentialRejectedException(RejectionReason.CREDENTIAL_NOT_YET_VALID,
                    "主体 " + subjectId + " 的凭证尚未到本地登记的生效时间 " + lc.notBefore());
        }
        if (lc.notAfter() != null && nowMillis > lc.notAfter()) {
            log.warn("生命周期拒绝: subject={}, now={}, notAfter={} 本地登记已失效",
                    subjectId, nowMillis, lc.notAfter());
            throw new CredentialRejectedException(RejectionReason.CREDENTIAL_EXPIRED,
                    "主体 " + subjectId + " 的凭证已超过本地登记的失效时间 " + lc.notAfter());
        }
    }

    /** 运行时撤销某主体的凭证（立即生效，HMAC1/HMAC2 统一适用）。 */
    public void revoke(String subjectId) {
        overrides.merge(subjectId, new Lifecycle(null, null, true),
                (old, v) -> new Lifecycle(old.notBefore(), old.notAfter(), true));
        log.info("运行时撤销凭证: subject={}", subjectId);
    }

    /** 仅供测试：清除运行时变更，恢复为配置初始值。 */
    public void reset() {
        overrides.clear();
    }

    private Lifecycle current(String subjectId) {
        Lifecycle override = overrides.get(subjectId);
        return override != null ? override : configured.get(subjectId);
    }

    private static Map<String, Lifecycle> parse(String raw) {
        Map<String, Lifecycle> result = new HashMap<>();
        if (!StringUtils.hasText(raw)) {
            return result;
        }
        for (String entry : raw.split(",")) {
            String item = entry.trim();
            if (item.isEmpty()) {
                continue;
            }
            int idx = item.indexOf(':');
            if (idx <= 0) {
                throw new IllegalArgumentException("非法凭证生命周期配置: " + item);
            }
            String subject = item.substring(0, idx).trim();
            String rest = item.substring(idx + 1).trim();

            if ("revoked".equalsIgnoreCase(rest)) {
                result.put(subject, new Lifecycle(null, null, true));
                continue;
            }

            String[] parts = rest.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("非法凭证生命周期配置（应为 notBefore:notAfter 或 revoked）: " + item);
            }
            Long notBefore = parseEpoch(parts[0], subject, "notBefore");
            Long notAfter = parseEpoch(parts[1], subject, "notAfter");
            result.put(subject, new Lifecycle(notBefore, notAfter, false));
        }
        return result;
    }

    private static Long parseEpoch(String raw, String subject, String field) {
        String v = raw.trim();
        if (v.isEmpty()) {
            return null;
        }
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "非法凭证生命周期配置: subject=" + subject + ", " + field + " 不是毫秒时间戳: " + v);
        }
    }

    /** 单个主体的本地生命周期登记；null 时间表示不限制该边界。 */
    private record Lifecycle(Long notBefore, Long notAfter, boolean revoked) {
    }
}
