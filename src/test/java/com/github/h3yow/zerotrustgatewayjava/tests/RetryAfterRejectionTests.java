package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayClock;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayDecision;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import com.github.h3yow.zerotrustgatewayjava.gateway.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.gateway.RejectionReason;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import com.github.h3yow.zerotrustgatewayjava.gateway.ZeroTrustGateway;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * “被拒之后重试”场景测试：
 * 限流拒绝不占去重名额、不推进序号水位，配额恢复后同一请求（同 requestId、同序号）
 * 可正常处理；鉴权失败同样不留痕；并发下限流拒绝与重试交错时，该拒的拒、该放的放。
 */
@SpringBootTest
@TestPropertySource(properties = {
        "zero-trust.gateway.quota-per-window=3",
        "zero-trust.gateway.window-millis=60000",
        "zero-trust.gateway.timestamp-skew-millis=30000",
        "zero-trust.gateway.replay-max-records-per-subject=100000"
})
class RetryAfterRejectionTests {

    private static final Logger log = LoggerFactory.getLogger(RetryAfterRejectionTests.class);

    @Autowired
    private ZeroTrustGateway gateway;
    @Autowired
    private LocalCredentialRegistry registry;
    @Autowired
    private RateLimiter rateLimiter;
    @Autowired
    private ReplayProtector replayProtector;
    @Autowired
    private GatewayClock gatewayClock;

    private final Instant t0 = Instant.parse("2026-10-03T00:00:00Z");
    private long seq;

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
        gatewayClock.setClock(Clock.fixed(t0, ZoneOffset.UTC));
        seq = 0;
    }

    @AfterEach
    void restoreClock() {
        gatewayClock.reset();
    }

    private GatewayRequest signed(String subject, String requestId, Long sequence) {
        long ts = gatewayClock.nowMillis();
        return SignedRequestFactory.signed(registry, "HMAC1", subject, subject,
                requestId, ts, sequence, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), ts + 600_000, null);
    }

    /**
     * 模拟真实调用方的重试：保持“同一个请求”的业务标识——同一 requestId 与序号，
     * 但时间戳用当前时钟重新生成并重新签名（旧时间戳已越过 skew 窗口，无法原样重放）。
     */
    private GatewayRequest retried(GatewayRequest original) {
        long ts = gatewayClock.nowMillis();
        return SignedRequestFactory.signed(registry, "HMAC1", original.claimedSubject(),
                original.claimedSubject(), original.requestId(), ts, original.sequence(),
                original.method(), original.path(), original.bodySha256(), ts + 600_000, null);
    }

    /** 把限流窗口滚动到恢复之后（模拟“等配额恢复”），确定性、无需真实 sleep。 */
    private void advanceWindowBeyondRecovery() {
        gatewayClock.setClock(Clock.fixed(t0.plusMillis(60_001), ZoneOffset.UTC));
    }

    @Test
    @DisplayName("限流重试：配额打满被 RATE_LIMITED 的同一请求，配额恢复后重试正常放行")
    void sameRequestSucceedsAfterQuotaRecovers() {
        // 用满配额 3
        for (int i = 1; i <= 3; i++) {
            assertTrue(gateway.evaluate(signed("alice", "retry-fill-" + i, (long) i)).allowed());
        }
        // 第 4 个请求被限流 —— 它携带固定 requestId 与序号
        GatewayRequest rejected = signed("alice", "retry-target", 4L);
        GatewayDecision first = gateway.evaluate(rejected);
        assertFalse(first.allowed());
        assertEquals(RejectionReason.RATE_LIMITED, first.reason());

        // 配额恢复后，调用方拿“同一个请求”（同 requestId、同序号；按真实行为用当前时间重签）重试
        advanceWindowBeyondRecovery();
        GatewayDecision retry = gateway.evaluate(retried(rejected));
        log.info("限流后重试结果: allowed={}, reason={}", retry.allowed(), retry.reason());
        assertTrue(retry.allowed(),
                "被限流的请求未占用去重名额，配额恢复后重试必须放行，实际=" + retry.reason());
    }

    @Test
    @DisplayName("限流拒绝不推进序号水位：重试后下一个序号合法请求不被误判回退")
    void rateLimitDoesNotAdvanceSequenceWatermark() {
        assertTrue(gateway.evaluate(signed("alice", "seq-fill-1", 1L)).allowed());
        assertTrue(gateway.evaluate(signed("alice", "seq-fill-2", 2L)).allowed());
        assertTrue(gateway.evaluate(signed("alice", "seq-fill-3", 3L)).allowed());

        GatewayRequest blocked = signed("alice", "seq-blocked", 4L);
        assertEquals(RejectionReason.RATE_LIMITED, gateway.evaluate(blocked).reason());

        advanceWindowBeyondRecovery();
        // 同一个 requestId/序号 4 的请求先重试成功（未被判回退，证明水位没被推进过）
        assertTrue(gateway.evaluate(retried(blocked)).allowed());
        // 序号 5 紧随其后也正常；序号 4 立刻再来才是窗口内重放（同 requestId 且仍在窗口内）
        assertTrue(gateway.evaluate(signed("alice", "seq-next", 5L)).allowed());
        // 用一个全新 requestId、但序号回到 4 的请求验证：水位只到 5，序号回退仍被拦
        assertEquals(RejectionReason.SEQUENCE_REGRESSION,
                gateway.evaluate(signed("alice", "seq-regress-check", 4L)).reason());
    }

    @Test
    @DisplayName("鉴权失败不留痕：伪造签名请求拒绝后，同 requestId 的合法签名请求仍可放行")
    void authFailureDoesNotOccupyDedupSlot() {
        GatewayRequest forged = SignedRequestFactory.withForgedSignature(
                signed("alice", "auth-slot", 1L));
        assertEquals(RejectionReason.SIGNATURE_MISMATCH, gateway.evaluate(forged).reason());
        // 鉴权阶段就被拒，去重与水位均未触碰：同 requestId、同序号的合法请求放行
        assertTrue(gateway.evaluate(signed("alice", "auth-slot", 1L)).allowed());
    }

    @Test
    @DisplayName("时间窗外的陈旧重试不登记：请求曾被 TIMESTAMP_OUT_OF_WINDOW 拒绝，时间基准对齐后放行")
    void timestampOutOfWindowDoesNotOccupySlot() {
        // 一个时间戳远在未来的请求（通过签名，但超出 skew 窗口）
        long futureTs = gatewayClock.nowMillis() + 120_000;
        GatewayRequest future = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                "future-req", futureTs, 1L, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), futureTs + 600_000, null);
        assertEquals(RejectionReason.TIMESTAMP_OUT_OF_WINDOW, gateway.evaluate(future).reason());

        // 时钟推进到该时间戳进入窗口后，同一请求可正常处理
        gatewayClock.setClock(Clock.fixed(Instant.ofEpochMilli(futureTs), ZoneOffset.UTC));
        assertTrue(gateway.evaluate(future).allowed(), "曾被时间窗拒绝的请求不应已被登记为重放");
    }

    @Test
    @DisplayName("并发交错：旧窗口并发全被限流；窗口滚动后同请求并发重试恰好放行 1 次，其余判重放")
    void concurrentRateLimitAndRetryInterleaving() throws InterruptedException {
        // 占满 3 个配额
        for (int i = 1; i <= 3; i++) {
            assertTrue(gateway.evaluate(signed("bob", "cc-fill-" + i, (long) i)).allowed());
        }
        final GatewayRequest blocked = signed("bob", "cc-target", 4L);

        int phaseOneThreads = 8;
        int phaseTwoThreads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(Math.max(phaseOneThreads, phaseTwoThreads));
        AtomicInteger rateLimited = new AtomicInteger();
        AtomicInteger replayed = new AtomicInteger();
        AtomicInteger allowed = new AtomicInteger();
        ConcurrentLinkedQueue<RejectionReason> others = new ConcurrentLinkedQueue<>();

        // 阶段一：旧窗口内，多线程同时提交同一被拒请求 → 必须全部限流，无一占去重名额
        CountDownLatch start1 = new CountDownLatch(1);
        CountDownLatch done1 = new CountDownLatch(phaseOneThreads);
        for (int i = 0; i < phaseOneThreads; i++) {
            pool.submit(() -> {
                try {
                    start1.await();
                    GatewayDecision d = gateway.evaluate(blocked);
                    if (d.allowed()) {
                        allowed.incrementAndGet();
                    } else if (d.reason() == RejectionReason.RATE_LIMITED) {
                        rateLimited.incrementAndGet();
                    } else {
                        others.add(d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done1.countDown();
                }
            });
        }
        start1.countDown();
        assertTrue(done1.await(30, TimeUnit.SECONDS), "阶段一应在超时前完成");
        log.info("并发交错-阶段一(旧窗口): RATE_LIMITED={}, 其他={}", rateLimited.get(), others);
        assertEquals(phaseOneThreads, rateLimited.get(), "旧窗口内并发请求必须全部被限流");
        assertTrue(others.isEmpty(), "旧窗口不应出现限流之外的结果: " + others);

        // “等配额恢复”：滚动窗口；调用方用当前时间重签同一 requestId/序号的请求
        advanceWindowBeyondRecovery();
        final GatewayRequest retryReq = retried(blocked);

        // 阶段二：新窗口内，多线程并发拿同一个请求重试 → 恰好 1 次成功，其余窗口内重放
        CountDownLatch start2 = new CountDownLatch(1);
        CountDownLatch done2 = new CountDownLatch(phaseTwoThreads);
        for (int i = 0; i < phaseTwoThreads; i++) {
            pool.submit(() -> {
                try {
                    start2.await();
                    GatewayDecision d = gateway.evaluate(retryReq);
                    if (d.allowed()) {
                        allowed.incrementAndGet();
                    } else if (d.reason() == RejectionReason.REPLAYED_REQUEST) {
                        replayed.incrementAndGet();
                    } else if (d.reason() == RejectionReason.RATE_LIMITED) {
                        rateLimited.incrementAndGet();
                    } else {
                        others.add(d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done2.countDown();
                }
            });
        }
        start2.countDown();
        assertTrue(done2.await(30, TimeUnit.SECONDS), "阶段二应在超时前完成");
        pool.shutdownNow();

        log.info("并发交错-阶段二(恢复后重试): 放行={}, REPLAYED_REQUEST={}, RATE_LIMITED={}, 其他={}",
                allowed.get(), replayed.get(), rateLimited.get() - phaseOneThreads, others);
        assertEquals(1, allowed.get(), "同一请求在配额恢复后只能有一次重试成功，不能重复放行");
        assertEquals(phaseTwoThreads - 1, replayed.get(),
                "新窗口侧除唯一成功者外必须全部识别为窗口内重放，该拒的不能漏");
        assertEquals(phaseOneThreads, rateLimited.get(), "不应有额外的限流误伤");
        assertTrue(others.isEmpty(), "不应出现限流/重放之外的拒绝: " + others);
    }
}
