package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.zerotrustgatewayjava.gateway.CredentialLifecycle;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayDecision;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import com.github.h3yow.zerotrustgatewayjava.gateway.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.gateway.RejectionReason;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import com.github.h3yow.zerotrustgatewayjava.gateway.ZeroTrustGateway;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 服务端集中凭证生命周期：生效/失效/撤销均以本地登记为准，HMAC1/HMAC2 两类凭证版本走同一判定。
 * 撤销、未生效、已失效与签名不符、主体不一致等原因彼此可区分。
 */
@SpringBootTest
class CredentialLifecycleTests {

    private static final Logger log = LoggerFactory.getLogger(CredentialLifecycleTests.class);

    private static final byte[] ALICE_KEY =
            Base64.getDecoder().decode("YWxpY2UtbG9jYWwtc2VjcmV0LWtleS0wMDAx");
    private static final byte[] BOB_KEY =
            Base64.getDecoder().decode("Ym9iLWxvY2FsLXNlY3JldC1rZXktMDAwMiEhIQ==");

    @Autowired
    private ZeroTrustGateway gateway;
    @Autowired
    private LocalCredentialRegistry registry;
    @Autowired
    private RateLimiter rateLimiter;
    @Autowired
    private ReplayProtector replayProtector;

    private long now;

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
        now = System.currentTimeMillis();
    }

    @AfterEach
    void restoreLifecycle() {
        registry.register("alice", ALICE_KEY, CredentialLifecycle.active());
        registry.register("bob", BOB_KEY, CredentialLifecycle.active());
    }

    private GatewayRequest signed(String version, String subject, String requestId, long seq) {
        return SignedRequestFactory.signed(registry, version, subject, subject,
                requestId, now + seq, seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{\"life\":true}"), now + 600_000, null);
    }

    private void assertRejected(GatewayDecision d, RejectionReason expected) {
        log.info("生命周期用例断言: 期望拒绝={}, 实际 allowed={}, reason={}, message={}",
                expected, d.allowed(), d.reason(), d.message());
        assertFalse(d.allowed());
        assertEquals(expected, d.reason(), "生命周期拒绝原因必须精确可区分");
        assertNotNull(d.message());
    }

    @Test
    @DisplayName("生命周期-有效：本地登记在窗口内的凭证，HMAC1 与 HMAC2 均放行")
    void locallyActiveCredentialsOfBothVersionsAreAllowed() {
        registry.register("alice", ALICE_KEY,
                new CredentialLifecycle(now - 1_000, now + 60_000, false));

        GatewayDecision d1 = gateway.evaluate(signed("HMAC1", "alice", "life-ok-1", 1));
        assertTrue(d1.allowed(), d1.message());
        GatewayDecision d2 = gateway.evaluate(signed("HMAC2", "alice", "life-ok-2", 2));
        assertTrue(d2.allowed(), d2.message());
        log.info("生命周期判定依据: 本地 [notBefore={}, notAfter={}]，两版本均 ACTIVE 放行",
                now - 1_000, now + 60_000);
    }

    @Test
    @DisplayName("生命周期-本地失效：登记 notAfter 已过，即使凭证头 expires 是未来也拒绝；两版本一致")
    void localExpiryWinsOverClientExpires() {
        registry.register("alice", ALICE_KEY,
                new CredentialLifecycle(null, now - 1_000, false));

        assertRejected(gateway.evaluate(signed("HMAC1", "alice", "life-exp-1", 1)),
                RejectionReason.CREDENTIAL_EXPIRED);
        assertRejected(gateway.evaluate(signed("HMAC2", "alice", "life-exp-2", 2)),
                RejectionReason.CREDENTIAL_EXPIRED);
    }

    @Test
    @DisplayName("生命周期-本地未生效：登记 notBefore 未到（凭证头自称仍有效），两版本均 CREDENTIAL_NOT_YET_VALID")
    void notYetValidIsRejectedForBothVersions() {
        registry.register("alice", ALICE_KEY,
                new CredentialLifecycle(now + 60_000, null, false));

        assertRejected(gateway.evaluate(signed("HMAC1", "alice", "life-future-1", 1)),
                RejectionReason.CREDENTIAL_NOT_YET_VALID);
        assertRejected(gateway.evaluate(signed("HMAC2", "alice", "life-future-2", 2)),
                RejectionReason.CREDENTIAL_NOT_YET_VALID);
    }

    @Test
    @DisplayName("生命周期-撤销：运行期 revoke 后立即拒绝（凭证头时间/签名均有效）；重新登记后恢复")
    void revokeTakesEffectImmediatelyAndReregisterRestores() {
        assertTrue(gateway.evaluate(signed("HMAC1", "alice", "life-rev-0", 1)).allowed());

        assertTrue(registry.revoke("alice"), "已登记主体应可撤销");
        assertRejected(gateway.evaluate(signed("HMAC1", "alice", "life-rev-1", 2)),
                RejectionReason.CREDENTIAL_REVOKED);
        assertRejected(gateway.evaluate(signed("HMAC2", "alice", "life-rev-2", 3)),
                RejectionReason.CREDENTIAL_REVOKED);

        // 重新发放凭证后恢复
        registry.register("alice", ALICE_KEY, CredentialLifecycle.active());
        assertTrue(gateway.evaluate(signed("HMAC1", "alice", "life-rev-3", 4)).allowed());
    }

    @Test
    @DisplayName("生命周期-撤销优先且可区分：撤销主体即使签名被伪造，仍判 CREDENTIAL_REVOKED 而非 SIGNATURE_MISMATCH")
    void revokedIsDistinctFromSignatureMismatch() {
        registry.revoke("bob");
        GatewayRequest forged = SignedRequestFactory.withForgedSignature(signed("HMAC1", "bob", "life-x-1", 1));
        assertRejected(gateway.evaluate(forged), RejectionReason.CREDENTIAL_REVOKED);
    }

    @Test
    @DisplayName("生命周期-原因可区分：未登记/密钥不符仍是 SIGNATURE_MISMATCH，未撤销的正常主体不受影响")
    void signatureMismatchRemainsDistinctAndOthersUnaffected() {
        // bob 被撤销不影响 alice
        registry.revoke("bob");
        assertTrue(gateway.evaluate(signed("HMAC1", "alice", "life-iso-1", 1)).allowed());

        // alice 用 bob 的密钥签名 -> SIGNATURE_MISMATCH（不被撤销原因掩盖）
        GatewayRequest wrongKey = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                "life-wrongkey", now + 2, 2L, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{\"life\":true}"), now + 600_000, "bob");
        assertRejected(gateway.evaluate(wrongKey), RejectionReason.SIGNATURE_MISMATCH);
    }
}
