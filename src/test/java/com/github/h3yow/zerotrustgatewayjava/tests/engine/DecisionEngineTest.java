package com.github.h3yow.zerotrustgatewayjava.tests.engine;

import com.github.h3yow.zerotrustgatewayjava.auth.RejectReason;
import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.config.GatewayProperties;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.credential.CredentialType;
import com.github.h3yow.zerotrustgatewayjava.engine.Decision;
import com.github.h3yow.zerotrustgatewayjava.engine.DefaultDecisionEngine;
import com.github.h3yow.zerotrustgatewayjava.ratelimit.LocalRateLimiter;
import com.github.h3yow.zerotrustgatewayjava.replay.InMemoryReplayGuard;
import com.github.h3yow.zerotrustgatewayjava.signature.HmacSignatureVerifier;
import com.github.h3yow.zerotrustgatewayjava.tests.TestSigning;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 判定主流程测试：覆盖正常、越权、篡改、重放、时间回退与并发限流边界。
 * 固定时钟 + 手动构造组件，用例可在本地直接运行。
 */
class DecisionEngineTest {

    private static final Logger log = LoggerFactory.getLogger(DecisionEngineTest.class);

    private static final Instant NOW = Instant.parse("2026-09-23T00:00:00Z");
    private static final long NOW_SECONDS = NOW.getEpochSecond();

    private static final Credential V1 = new Credential(
            "demo-key-v1", "local-demo-secret-v1", CredentialType.V1_HMAC_SHA1,
            "svc-demo", Instant.parse("2099-01-01T00:00:00Z"));
    private static final Credential V2 = new Credential(
            "demo-key-v2", "local-demo-secret-v2", CredentialType.V2_HMAC_SHA256,
            "svc-demo", Instant.parse("2099-01-01T00:00:00Z"));
    private static final Credential PARTNER = new Credential(
            "partner-key-v2", "local-partner-secret", CredentialType.V2_HMAC_SHA256,
            "svc-partner", Instant.parse("2099-01-01T00:00:00Z"));
    private static final Credential EXPIRED = new Credential(
            "expired-key-v1", "local-expired-secret", CredentialType.V1_HMAC_SHA1,
            "svc-expired", Instant.parse("2020-01-01T00:00:00Z"));

    /** 可推进的固定时钟。 */
    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private static GatewayProperties props(long rateLimit, long windowSeconds, long tsWindow, long nonceTtl) {
        return new GatewayProperties(
                tsWindow, nonceTtl, rateLimit, windowSeconds,
                List.of(
                        new GatewayProperties.CredentialConfig(V1.keyId(), V1.secret(), V1.type().name(),
                                V1.principal(), V1.expiresAt()),
                        new GatewayProperties.CredentialConfig(V2.keyId(), V2.secret(), V2.type().name(),
                                V2.principal(), V2.expiresAt()),
                        new GatewayProperties.CredentialConfig(PARTNER.keyId(), PARTNER.secret(),
                                PARTNER.type().name(), PARTNER.principal(), PARTNER.expiresAt()),
                        new GatewayProperties.CredentialConfig(EXPIRED.keyId(), EXPIRED.secret(),
                                EXPIRED.type().name(), EXPIRED.principal(), EXPIRED.expiresAt())));
    }

    private static DefaultDecisionEngine newEngine(MutableClock clock, long rateLimit) {
        GatewayProperties p = props(rateLimit, 10, 30, 120);
        return new DefaultDecisionEngine(
                new com.github.h3yow.zerotrustgatewayjava.credential.LocalCredentialStore(p),
                new HmacSignatureVerifier(),
                new LocalRateLimiter(p, clock),
                new InMemoryReplayGuard(p),
                p,
                clock);
    }

    private static RequestContext validRequest(Credential credential, String nonce, long sequence) {
        byte[] body = ("hello-" + nonce).getBytes();
        return TestSigning.signedRequest("POST", "/api/echo", body,
                credential.keyId(), credential.principal(), NOW_SECONDS, nonce, sequence, credential);
    }

    @Test
    @DisplayName("正常请求：V1(HMAC-SHA1) 与 V2(HMAC-SHA256) 归一到同一主体并放行")
    void allowsBothCredentialVersionsWithSamePrincipal() {
        MutableClock clock = new MutableClock(NOW);
        DefaultDecisionEngine engine = newEngine(clock, 10);

        Decision v1 = engine.evaluate(validRequest(V1, "nonce-1", 1));
        Decision v2 = engine.evaluate(validRequest(V2, "nonce-2", 2));

        log.info("v1 decision: allowed={} principal={} reason={}", v1.allowed(), v1.principal(), v1.reason());
        log.info("v2 decision: allowed={} principal={} reason={}", v2.allowed(), v2.principal(), v2.reason());

        assertThat(v1.allowed()).isTrue();
        assertThat(v2.allowed()).isTrue();
        assertThat(v1.principal()).isEqualTo("svc-demo");
        assertThat(v2.principal()).isEqualTo("svc-demo");
    }

    @Test
    @DisplayName("凭证缺失 -> MISSING_CREDENTIAL")
    void missingCredential() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext request = new RequestContext("POST", "/api/echo", new byte[0],
                null, null, NOW_SECONDS, "n", 1L, "h", "s");

        Decision decision = engine.evaluate(request);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.MISSING_CREDENTIAL);
    }

    @Test
    @DisplayName("未知 keyId -> UNKNOWN_KEY_ID")
    void unknownKeyId() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext request = new RequestContext("POST", "/api/echo", new byte[0],
                "does-not-exist", null, NOW_SECONDS, "n", 1L, "h", "s");

        Decision decision = engine.evaluate(request);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.UNKNOWN_KEY_ID);
    }

    @Test
    @DisplayName("凭证过期 -> CREDENTIAL_EXPIRED（即便签名合法）")
    void expiredCredential() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        Decision decision = engine.evaluate(validRequest(EXPIRED, "nonce-1", 1));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.CREDENTIAL_EXPIRED);
    }

    @Test
    @DisplayName("自述主体与凭证主体不一致 -> PRINCIPAL_MISMATCH（越权）")
    void principalMismatch() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext request = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                V1.keyId(), "svc-attacker", NOW_SECONDS, "nonce-1", 1, V1);

        Decision decision = engine.evaluate(request);

        log.info("impersonation attempt denied: reason={} detail={}", decision.reason(), decision.detail());
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.PRINCIPAL_MISMATCH);
    }

    @Test
    @DisplayName("篡改请求体（bodyHash 不重算）-> BODY_TAMPERED")
    void tamperedBody() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext signed = validRequest(V1, "nonce-1", 1);
        // 签名头保持原样，但请求体被改动
        RequestContext tampered = new RequestContext(signed.method(), signed.path(),
                "tampered-payload".getBytes(), signed.keyId(), signed.claimedPrincipal(),
                signed.timestamp(), signed.nonce(), signed.sequence(),
                signed.bodyHash(), signed.signature());

        Decision decision = engine.evaluate(tampered);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.BODY_TAMPERED);
    }

    @Test
    @DisplayName("签名被改坏 -> SIGNATURE_MISMATCH，且与 BODY_TAMPERED 可区分")
    void badSignature() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext signed = validRequest(V1, "nonce-1", 1);
        RequestContext badSig = TestSigning.withSignature(signed, signed.signature().replace('a', 'b'));

        Decision decision = engine.evaluate(badSig);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.SIGNATURE_MISMATCH);
    }

    @Test
    @DisplayName("用其他主体凭证对请求签名 -> SIGNATURE_MISMATCH（跨凭证不可伪造）")
    void signatureFromOtherCredentialRejected() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        // 请求声称自己是 partner，却用 demo 的密钥签名
        RequestContext request = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                PARTNER.keyId(), PARTNER.principal(), NOW_SECONDS, "nonce-1", 1, V1);

        Decision decision = engine.evaluate(request);

        assertThat(decision.reason()).isEqualTo(RejectReason.SIGNATURE_MISMATCH);
    }

    @Test
    @DisplayName("时间戳超出窗口 -> STALE_TIMESTAMP")
    void staleTimestamp() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext request = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                V1.keyId(), V1.principal(), NOW_SECONDS - 31, "nonce-1", 1, V1);

        Decision decision = engine.evaluate(request);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.STALE_TIMESTAMP);
    }

    @Test
    @DisplayName("缺少/畸形数值头 -> MALFORMED_REQUEST")
    void malformedRequest() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 10);
        RequestContext request = new RequestContext("POST", "/api/echo", new byte[0],
                V1.keyId(), V1.principal(), null, "nonce-1", null, null, null);

        Decision decision = engine.evaluate(request);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).isEqualTo(RejectReason.MALFORMED_REQUEST);
    }

    @Test
    @DisplayName("同一 nonce 重复提交 -> NONCE_REPLAY，且判定稳定可复现")
    void nonceReplayIsDetectedAndStable() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 100);
        RequestContext first = validRequest(V1, "shared-nonce", 1);
        RequestContext replay = TestSigning.withSequence(validRequest(V1, "shared-nonce", 2), 2);

        Decision d1 = engine.evaluate(first);
        Decision d2 = engine.evaluate(replay);
        Decision d3 = engine.evaluate(replay);

        log.info("replay sequence: first={}, second={}, third={}", d1.reason(), d2.reason(), d3.reason());
        assertThat(d1.allowed()).isTrue();
        assertThat(d2.allowed()).isFalse();
        assertThat(d3.allowed()).isFalse();
        assertThat(d2.reason()).isEqualTo(RejectReason.NONCE_REPLAY);
        // 同一重复输入，结论稳定
        assertThat(d3.reason()).isEqualTo(RejectReason.NONCE_REPLAY);
    }

    @Test
    @DisplayName("序号回退 -> SEQUENCE_ROLLBACK，即使 nonce 不同")
    void sequenceRollbackDetected() {
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), 100);
        RequestContext newer = validRequest(V1, "nonce-10", 10);
        RequestContext older = validRequest(V1, "nonce-9", 9);

        assertThat(engine.evaluate(newer).allowed()).isTrue();
        Decision rollback = engine.evaluate(older);

        assertThat(rollback.allowed()).isFalse();
        assertThat(rollback.reason()).isEqualTo(RejectReason.SEQUENCE_ROLLBACK);
    }

    @Test
    @DisplayName("nonce 超过 TTL 后可复用")
    void nonceReusableAfterTtl() {
        MutableClock clock = new MutableClock(NOW);
        DefaultDecisionEngine engine = newEngine(clock, 100);

        assertThat(engine.evaluate(validRequest(V1, "same-nonce", 1)).allowed()).isTrue();
        clock.advanceSeconds(121);
        // 时间戳窗口仅 30s，第二个请求必须用推进后的当前时间重新签名
        byte[] body = "hello-same-nonce".getBytes();
        RequestContext second = TestSigning.signedRequest("POST", "/api/echo", body,
                V1.keyId(), V1.principal(), NOW_SECONDS + 121, "same-nonce", 2, V1);
        Decision again = engine.evaluate(second);

        assertThat(again.allowed()).isTrue();
    }

    @Test
    @DisplayName("限流边界：串行下恰好放行配额数，下一次 RATE_LIMITED，且与鉴权原因不同")
    void rateLimitBoundarySerial() {
        long limit = 5;
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), limit);

        for (int i = 1; i <= limit; i++) {
            Decision d = engine.evaluate(validRequest(V1, "nonce-" + i, i));
            assertThat(d.allowed())
                    .as("request %d within quota must pass", i)
                    .isTrue();
            assertThat(d.rateLimitRemaining()).isEqualTo(limit - i);
        }

        Decision overflow = engine.evaluate(validRequest(V1, "nonce-overflow", limit + 1));
        log.info("overflow decision: reason={} detail={}", overflow.reason(), overflow.detail());
        assertThat(overflow.allowed()).isFalse();
        assertThat(overflow.reason()).isEqualTo(RejectReason.RATE_LIMITED);
    }

    @Test
    @DisplayName("限流按主体隔离：partner 不受 demo 配额影响")
    void rateLimitIsPerPrincipal() {
        long limit = 2;
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), limit);

        engine.evaluate(validRequest(V1, "d1", 1));
        engine.evaluate(validRequest(V1, "d2", 2));
        Decision demoOverflow = engine.evaluate(validRequest(V1, "d3", 3));
        Decision partner = engine.evaluate(validRequest(PARTNER, "p1", 1));

        assertThat(demoOverflow.reason()).isEqualTo(RejectReason.RATE_LIMITED);
        assertThat(partner.allowed()).isTrue();
    }

    @Test
    @DisplayName("并发竞态（限流器层）：同主体突发请求实际放行量恰好等于配额，无丢失/超发")
    void concurrentBurstAtLimiterNeverExceedsQuota() throws InterruptedException {
        long limit = 20;
        int threads = 200;
        MutableClock clock = new MutableClock(NOW);
        GatewayProperties p = props(limit, 10, 30, 120);
        LocalRateLimiter limiter = new LocalRateLimiter(p, clock);

        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger limited = new AtomicInteger();

        IntStream.range(0, threads).forEach(i ->
                pool.submit(() -> {
                    try {
                        start.await();
                        if (limiter.tryAcquire("svc-demo").allowed()) {
                            allowed.incrementAndGet();
                        } else {
                            limited.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                }));

        start.countDown();
        assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        log.info("concurrent burst at limiter: threads={}, allowed={}, rateLimited={}, quota={}",
                threads, allowed.get(), limited.get(), limit);

        assertThat(allowed.get()).as("实际放行量必须恰好等于配额").isEqualTo(limit);
        assertThat(limited.get()).isEqualTo(threads - limit);
        assertThat(allowed.get() + limited.get()).isEqualTo(threads);
    }

    @Test
    @DisplayName("并发竞态（端到端）：同一请求多线程并发提交，恰好一个通过，其余 NONCE_REPLAY，无静默重复通过")
    void concurrentSameRequestOnlyOneWins() throws InterruptedException {
        long limit = 100;
        MutableClock clock = new MutableClock(NOW);
        DefaultDecisionEngine engine = newEngine(clock, limit);
        RequestContext request = validRequest(V1, "race-nonce", 1);

        int threads = 64;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger replays = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    Decision d = engine.evaluate(request);
                    if (d.allowed()) {
                        allowed.incrementAndGet();
                    } else if (d.reason() == RejectReason.NONCE_REPLAY) {
                        replays.incrementAndGet();
                    } else {
                        other.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        log.info("same-request race: threads={}, allowed={}, nonceReplay={}, other={}",
                threads, allowed.get(), replays.get(), other.get());

        assertThat(allowed.get()).as("同一请求并发提交必须恰好通过一次").isEqualTo(1);
        assertThat(replays.get()).isEqualTo(threads - 1);
        assertThat(other.get()).isZero();
    }

    @Test
    @DisplayName("重放拒绝不永久占用配额：被 NONCE_REPLAY 拒绝后额度归还，窗口内仍可放满配额")
    void replayRejectionReleasesQuota() {
        long limit = 3;
        DefaultDecisionEngine engine = newEngine(new MutableClock(NOW), limit);

        // 先放一个请求占用 seq=1 / nonce-a
        assertThat(engine.evaluate(validRequest(V1, "nonce-a", 1)).allowed()).isTrue();
        // 两个重复 nonce 被拒（序号前进但 nonce 重复），应归还额度
        Decision replay1 = engine.evaluate(validRequest(V1, "nonce-a", 2));
        Decision replay2 = engine.evaluate(validRequest(V1, "nonce-a", 3));
        assertThat(replay1.reason()).isEqualTo(RejectReason.NONCE_REPLAY);
        assertThat(replay2.reason()).isEqualTo(RejectReason.NONCE_REPLAY);

        // 若额度未归还，这里只能再放 1 个；归还后应还能放 2 个
        assertThat(engine.evaluate(validRequest(V1, "nonce-b", 4)).allowed()).isTrue();
        Decision last = engine.evaluate(validRequest(V1, "nonce-c", 5));
        assertThat(last.allowed())
                .as("replay denials must release their acquired quota")
                .isTrue();
        // 第 4 个唯一请求才触发限流：配额没有被重放拒绝吞掉
        assertThat(engine.evaluate(validRequest(V1, "nonce-d", 6)).reason())
                .isEqualTo(RejectReason.RATE_LIMITED);
    }
}
