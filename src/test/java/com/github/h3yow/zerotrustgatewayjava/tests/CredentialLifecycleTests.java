package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayDecision;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import com.github.h3yow.zerotrustgatewayjava.gateway.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.gateway.RejectionReason;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import com.github.h3yow.zerotrustgatewayjava.gateway.ZeroTrustGateway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * 服务端集中凭证生命周期测试：
 * 生效窗口内放行、未到生效时间、超过失效时间、运行时撤销，以及 HMAC1/HMAC2
 * 两个凭证版本走同一套本地登记判定；本地登记权威，覆盖客户端自带 expires。
 */
@SpringBootTest
@TestPropertySource(properties = {
        "zero-trust.gateway.credentials="
                + "carol:Y2Fyb2wtbG9jYWwtc2VjcmV0LWtleS0wMDAzISEh,"
                + "dave:Y2Fyb2wtbG9jYWwtc2VjcmV0LWtleS0wMDAzISEh,"
                + "erin:Y2Fyb2wtbG9jYWwtc2VjcmV0LWtleS0wMDAzISEh,"
                + "frank:Y2Fyb2wtbG9jYWwtc2VjcmV0LWtleS0wMDAzISEh",
        "zero-trust.gateway.credential-lifecycles="
                // carol：窗口内有效（覆盖全部测试执行时间）
                + "carol:1700000000000:1800000000000,"
                // dave：尚未生效（1900000000000 = 2030 年）
                + "dave:1900000000000:1950000000000,"
                // erin：已经失效（边界用 notAfter 略早于当前）
                + "erin::1700000000000,"
        // frank 不登记生命周期：验证未配置主体不受约束、与旧版配置兼容
})
class CredentialLifecycleTests {

    private static final Logger log = LoggerFactory.getLogger(CredentialLifecycleTests.class);

    @Autowired
    private ZeroTrustGateway gateway;
    @Autowired
    private LocalCredentialRegistry registry;
    @Autowired
    private RateLimiter rateLimiter;
    @Autowired
    private ReplayProtector replayProtector;
    @Autowired
    private com.github.h3yow.zerotrustgatewayjava.gateway.CredentialLifecycleManager lifecycleManager;

    private long now;
    private long seq;

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
        lifecycleManager.reset();
        now = System.currentTimeMillis();
        seq = 0;
    }

    private GatewayRequest request(String version, String subject, String requestId) {
        return SignedRequestFactory.signed(registry, version, subject, subject,
                requestId, now, ++seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), now + 600_000, null);
    }

    private void assertRejected(GatewayDecision d, RejectionReason expected) {
        log.info("生命周期用例断言: 期望拒绝={}, 实际 allowed={}, reason={}, message={}",
                expected, d.allowed(), d.reason(), d.message());
        assertFalse(d.allowed());
        assertEquals(expected, d.reason());
        assertNotNull(d.message());
    }

    @Test
    @DisplayName("生命周期：窗口内的主体，HMAC1 与 HMAC2 两种凭证版本都放行")
    void activeCredentialAllowedForBothVersions() {
        assertTrue(gateway.evaluate(request("HMAC1", "carol", "lc-carol-v1")).allowed());
        assertTrue(gateway.evaluate(request("HMAC2", "carol", "lc-carol-v2")).allowed());
    }

    @Test
    @DisplayName("生命周期：未登记的主体不受约束（旧配置兼容）")
    void unregisteredLifecycleSubjectIsUnconstrained() {
        assertTrue(gateway.evaluate(request("HMAC1", "frank", "lc-frank-1")).allowed());
    }

    @Test
    @DisplayName("生命周期：本地登记未到生效时间，两种凭证版本都 CREDENTIAL_NOT_YET_VALID")
    void notYetValidIsRejectedForBothVersions() {
        assertRejected(gateway.evaluate(request("HMAC1", "dave", "lc-dave-v1")),
                RejectionReason.CREDENTIAL_NOT_YET_VALID);
        assertRejected(gateway.evaluate(request("HMAC2", "dave", "lc-dave-v2")),
                RejectionReason.CREDENTIAL_NOT_YET_VALID);
    }

    @Test
    @DisplayName("生命周期：本地登记已失效，两种凭证版本都 CREDENTIAL_EXPIRED")
    void expiredByLocalRegistryIsRejectedForBothVersions() {
        assertRejected(gateway.evaluate(request("HMAC1", "erin", "lc-erin-v1")),
                RejectionReason.CREDENTIAL_EXPIRED);
        assertRejected(gateway.evaluate(request("HMAC2", "erin", "lc-erin-v2")),
                RejectionReason.CREDENTIAL_EXPIRED);
    }

    @Test
    @DisplayName("生命周期权威：凭证头自带 expires 仍有效，但本地登记已失效 → 仍以本地为准拒绝")
    void localExpiryOverridesClientExpires() {
        // erin 本地 notAfter=1700000000000（已过），但请求头 expires 故意签成未来 10 分钟
        GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC2", "erin", "erin",
                "lc-erin-client-future", now, ++seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), now + 600_000, null);
        assertRejected(gateway.evaluate(r), RejectionReason.CREDENTIAL_EXPIRED);
    }

    @Test
    @DisplayName("生命周期：运行时撤销生效，两种凭证版本都 CREDENTIAL_REVOKED；与签名/主体原因可区分")
    void runtimeRevocationRejectsBothVersions() {
        // 撤销前正常
        assertTrue(gateway.evaluate(request("HMAC1", "carol", "lc-carol-before-revoke")).allowed());

        lifecycleManager.revoke("carol");

        assertRejected(gateway.evaluate(request("HMAC1", "carol", "lc-carol-revoked-v1")),
                RejectionReason.CREDENTIAL_REVOKED);
        assertRejected(gateway.evaluate(request("HMAC2", "carol", "lc-carol-revoked-v2")),
                RejectionReason.CREDENTIAL_REVOKED);
    }

    @Test
    @DisplayName("生命周期：配置中标记 revoked 的主体直接拒绝（两类版本一致）")
    void configuredRevocationRejects() {
        lifecycleManager.revoke("frank");
        assertRejected(gateway.evaluate(request("HMAC1", "frank", "lc-frank-revoked-v1")),
                RejectionReason.CREDENTIAL_REVOKED);
        assertRejected(gateway.evaluate(request("HMAC2", "frank", "lc-frank-revoked-v2")),
                RejectionReason.CREDENTIAL_REVOKED);
    }

    @Test
    @DisplayName("生命周期原因与签名不符/主体不一致明确区分：被撤销主体伪造签名仍是 CREDENTIAL_REVOKED")
    void revocationCheckedBeforeSignatureDistinction() {
        lifecycleManager.revoke("carol");
        // 已撤销 + 伪造签名：本地生命周期先判定，原因稳定为撤销而非签名不符
        GatewayRequest forged = SignedRequestFactory.withForgedSignature(
                request("HMAC1", "carol", "lc-carol-forged"));
        assertRejected(gateway.evaluate(forged), RejectionReason.CREDENTIAL_REVOKED);
    }
}
