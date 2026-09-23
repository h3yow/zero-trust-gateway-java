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

/**
 * 网关闭环测试：正常、越权、过期、篡改、重放、序号回退、限流边界。
 * 所有断言均校验可区分的拒绝原因；输入与判定依据在应用日志中打印。
 */
@SpringBootTest
class ZeroTrustGatewayTests {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustGatewayTests.class);

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

    private GatewayRequest fresh(String version, String subject, String requestId, long seq) {
        return SignedRequestFactory.signed(registry, version, subject, requestId, now + seq, seq,
                "POST", "/api/echo", SignedRequestFactory.bodySha256("{\"k\":\"v\"}"));
    }

    private void assertRejected(GatewayDecision d, RejectionReason expected) {
        log.info("用例断言: 期望拒绝={}, 实际 allowed={}, reason={}, message={}",
                expected, d.allowed(), d.reason(), d.message());
        assertFalse(d.allowed(), "应当被拒绝");
        assertEquals(expected, d.reason(), "拒绝原因必须可区分且精确匹配");
        assertNotNull(d.message());
    }

    @Test
    @DisplayName("正常：HMAC1(v1) 与 HMAC2(v2) 凭证均归一到同一主体并放行")
    void validCredentialsOfBothVersionsAreAllowed() {
        GatewayDecision d1 = gateway.evaluate(fresh("HMAC1", "alice", "req-h1-1", 1));
        assertTrue(d1.allowed());
        assertEquals("alice", d1.principal().subjectId());
        assertEquals("HMAC1", d1.principal().credentialType());

        GatewayDecision d2 = gateway.evaluate(fresh("HMAC2", "alice", "req-h2-1", 2));
        assertTrue(d2.allowed());
        assertEquals("alice", d2.principal().subjectId());
        assertEquals("HMAC2", d2.principal().credentialType());
    }

    @Test
    @DisplayName("越权：凭证缺失")
    void missingCredentialIsRejected() {
        GatewayRequest r = new GatewayRequest(null, "alice", "req-x", now, 1L,
                "POST", "/api/echo", SignedRequestFactory.bodySha256(""));
        assertRejected(gateway.evaluate(r), RejectionReason.MISSING_CREDENTIAL);
    }

    @Test
    @DisplayName("越权：未知凭证类型")
    void unknownCredentialTypeIsRejected() {
        GatewayRequest r = new GatewayRequest("BEARER something", "alice", "req-x", now, 1L,
                "POST", "/api/echo", SignedRequestFactory.bodySha256(""));
        assertRejected(gateway.evaluate(r), RejectionReason.UNKNOWN_CREDENTIAL_TYPE);
    }

    @Test
    @DisplayName("越权：凭证结构残缺")
    void malformedCredentialIsRejected() {
        GatewayRequest r = new GatewayRequest("HMAC1 keyId=alice", "alice", "req-x", now, 1L,
                "POST", "/api/echo", SignedRequestFactory.bodySha256(""));
        assertRejected(gateway.evaluate(r), RejectionReason.MALFORMED_CREDENTIAL);
    }

    @Test
    @DisplayName("越权：伪造签名（签名不符，区别于主体不一致）")
    void forgedSignatureIsRejected() {
        GatewayRequest r = SignedRequestFactory.withForgedSignature(fresh("HMAC1", "alice", "req-forged", 1));
        assertRejected(gateway.evaluate(r), RejectionReason.SIGNATURE_MISMATCH);
    }

    @Test
    @DisplayName("越权：正文被篡改导致签名不符")
    void tamperedBodyIsRejected() {
        GatewayRequest original = fresh("HMAC1", "alice", "req-tamper", 1);
        GatewayRequest tampered = new GatewayRequest(original.credentialHeader(), original.claimedSubject(),
                original.requestId(), original.timestamp(), original.sequence(), original.method(),
                original.path(), SignedRequestFactory.bodySha256("{\"k\":\"attacker\"}"));
        assertRejected(gateway.evaluate(tampered), RejectionReason.SIGNATURE_MISMATCH);
    }

    @Test
    @DisplayName("越权：凭证过期（区别于签名不符）")
    void expiredCredentialIsRejected() {
        GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                "req-expired", now, 1L, "POST", "/api/echo", SignedRequestFactory.bodySha256(""),
                now - 1, null);
        assertRejected(gateway.evaluate(r), RejectionReason.CREDENTIAL_EXPIRED);
    }

    @Test
    @DisplayName("越权：请求声明主体与凭证内嵌主体不一致")
    void principalMismatchIsRejected() {
        // 凭证内嵌 alice，但请求头声明 bob
        GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC2", "alice", "bob",
                "req-mismatch", now, 1L, "POST", "/api/echo", SignedRequestFactory.bodySha256(""),
                now + 600_000, null);
        assertRejected(gateway.evaluate(r), RejectionReason.PRINCIPAL_MISMATCH);
    }

    @Test
    @DisplayName("越权：用其他主体的密钥签名")
    void wrongSigningKeyIsRejected() {
        // alice 的凭证，但用 bob 的密钥做签名
        GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                "req-wrongkey", now, 1L, "POST", "/api/echo", SignedRequestFactory.bodySha256(""),
                now + 600_000, "bob");
        assertRejected(gateway.evaluate(r), RejectionReason.SIGNATURE_MISMATCH);
    }

    @Test
    @DisplayName("重放要素：缺少 requestId / 缺少 timestamp 分别可区分")
    void missingReplayHeadersAreRejectedDistinctly() {
        // 基于已正确签名的请求，仅移除对应头，保证签名先通过、由防重放层拒绝
        GatewayRequest valid1 = fresh("HMAC1", "alice", "req-noid", 1);
        GatewayRequest noId = new GatewayRequest(valid1.credentialHeader(),
                "alice", null, valid1.timestamp(), valid1.sequence(),
                valid1.method(), valid1.path(), valid1.bodySha256());
        assertRejected(gateway.evaluate(noId), RejectionReason.MISSING_REQUEST_ID);

        GatewayRequest valid2 = fresh("HMAC1", "alice", "req-nots", 2);
        GatewayRequest noTs = new GatewayRequest(valid2.credentialHeader(),
                "alice", valid2.requestId(), null, valid2.sequence(),
                valid2.method(), valid2.path(), valid2.bodySha256());
        assertRejected(gateway.evaluate(noTs), RejectionReason.MISSING_TIMESTAMP);
    }

    @Test
    @DisplayName("重放：时间戳超出有效窗口")
    void timestampOutOfWindowIsRejected() {
        GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                "req-old", now - 120_000, 1L, "POST", "/api/echo", SignedRequestFactory.bodySha256(""));
        assertRejected(gateway.evaluate(r), RejectionReason.TIMESTAMP_OUT_OF_WINDOW);
    }

    @Test
    @DisplayName("重放：同一 requestId 重复提交，第二次稳定识别为 REPLAYED_REQUEST")
    void duplicateRequestIdIsReplay() {
        GatewayRequest r = fresh("HMAC1", "alice", "req-dup", 1);
        assertTrue(gateway.evaluate(r).allowed());
        GatewayDecision again = gateway.evaluate(r);
        assertRejected(again, RejectionReason.REPLAYED_REQUEST);
        // 同一输入结论稳定可复现：第三次仍是重放
        assertRejected(gateway.evaluate(r), RejectionReason.REPLAYED_REQUEST);
    }

    @Test
    @DisplayName("重放：序号/时间回退被识别（且区别于重复 ID）")
    void sequenceRegressionIsRejected() {
        assertTrue(gateway.evaluate(fresh("HMAC1", "alice", "req-seq-1", 10)).allowed());
        // 新的 requestId，时间戳相同但序号变小 → 回退
        GatewayRequest regressed = fresh("HMAC1", "alice", "req-seq-2", 9);
        assertRejected(gateway.evaluate(regressed), RejectionReason.SEQUENCE_REGRESSION);
    }

    @Test
    @DisplayName("判定稳定：除 requestId/序号外完全相同的两次输入均可放行（结果只随输入与状态确定）")
    void distinctIdsWithSamePayloadAreDeterministic() {
        String body = SignedRequestFactory.bodySha256("{\"same\":true}");
        GatewayRequest a = SignedRequestFactory.signed(registry, "HMAC1", "bob", "req-det-1",
                now, 1L, "POST", "/api/echo", body);
        GatewayRequest b = SignedRequestFactory.signed(registry, "HMAC1", "bob", "req-det-2",
                now + 1, 2L, "POST", "/api/echo", body);
        assertTrue(gateway.evaluate(a).allowed());
        assertTrue(gateway.evaluate(b).allowed());
    }

    @Test
    @DisplayName("限流边界：恰好放满配额，第 quota+1 个被 RATE_LIMITED（与鉴权/重放原因不同）")
    void rateLimitBoundaryIsExact() {
        int quota = 5; // application.properties: zero-trust.gateway.quota-per-window=5
        for (int i = 1; i <= quota; i++) {
            GatewayDecision d = gateway.evaluate(fresh("HMAC1", "alice", "req-quota-" + i, i));
            assertTrue(d.allowed(), "第 " + i + " 个请求应在配额内放行");
        }
        assertRejected(gateway.evaluate(fresh("HMAC1", "alice", "req-quota-over", quota + 1)),
                RejectionReason.RATE_LIMITED);
    }

    @Test
    @DisplayName("限流语义：被重放/鉴权拒绝的请求不占用配额，额度不会被永久占用")
    void rejectedRequestsDoNotConsumeQuota() {
        // 用掉 4 个配额
        for (int i = 1; i <= 4; i++) {
            assertTrue(gateway.evaluate(fresh("HMAC1", "alice", "req-keep-" + i, i)).allowed());
        }
        // 若干注定被重放/鉴权拒绝的请求
        GatewayRequest valid = fresh("HMAC1", "alice", "req-keep-1", 1);
        assertRejected(gateway.evaluate(valid), RejectionReason.REPLAYED_REQUEST);
        assertRejected(gateway.evaluate(
                SignedRequestFactory.withForgedSignature(fresh("HMAC1", "alice", "req-keep-forged", 5))),
                RejectionReason.SIGNATURE_MISMATCH);
        // 第 5 个合法请求仍可放行 —— 证明拒绝没有吃掉额度
        assertTrue(gateway.evaluate(fresh("HMAC1", "alice", "req-keep-5", 6)).allowed());
        // 第 6 个才超限
        assertRejected(gateway.evaluate(fresh("HMAC1", "alice", "req-keep-6", 7)),
                RejectionReason.RATE_LIMITED);
    }
}
