package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 服务端集中登记的凭证生命周期，判定一律以本地登记为准，与客户端凭证头里自带的时间/状态无关。
 *
 * @param notBefore 生效时间（epochMillis），null 表示不设下限
 * @param notAfter  失效时间（epochMillis），null 表示不设上限
 * @param revoked   是否已被服务端撤销；撤销优先级最高
 */
public record CredentialLifecycle(Long notBefore, Long notAfter, boolean revoked) {

    public static CredentialLifecycle active() {
        return new CredentialLifecycle(null, null, false);
    }

    public CredentialLifecycle asRevoked() {
        return new CredentialLifecycle(notBefore, notAfter, true);
    }

    /** 以本地时钟 {@code now} 判定当前状态；撤销优先于时间窗口。 */
    public Status statusAt(long now) {
        if (revoked) {
            return Status.REVOKED;
        }
        if (notBefore != null && now < notBefore) {
            return Status.NOT_YET_VALID;
        }
        if (notAfter != null && now > notAfter) {
            return Status.EXPIRED;
        }
        return Status.ACTIVE;
    }

    /** 本地登记的生命周期状态。 */
    public enum Status {
        ACTIVE,
        NOT_YET_VALID,
        EXPIRED,
        REVOKED
    }
}
