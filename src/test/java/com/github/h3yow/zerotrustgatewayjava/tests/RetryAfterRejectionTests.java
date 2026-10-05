package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayDecision;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayProperties;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import com.github.h3yow.zerotrustgatewayjava.gateway.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.gateway.RejectionReason;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import com.github.h3yow.zerotrustgatewayjava.gateway.ZeroTrustGateway;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * “被拒之后重试”：
 * <ul>
 *   <li>配额打满被拒的请求不登记 requestId、不推进序号水位，配额恢复后同一请求重试可正常处理；</li>
 *   <li>鉴权失败/被限流的请求不占去重名额，也不消耗后续合法请求的额度；</li>
 *   <li>并发下限流拒绝与重试交错，该拒的拒、该放的放。</li>
 * </ul>
 */
@SpringBootTest
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
    private GatewayProperties properties;

    private long now;

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
        now = System.currentTimeMillis();
    }

    private static void assertRejected(GatewayDecision d, RejectionReason expected) {
        assertFalse(d.allowed());
        assertEquals(expected, d.reason());
    }

    @Test
    @DisplayName("重试：同一请求（同 requestId/序号）先因配额满被拒，配额恢复后重试应正常放行")
    void rateLimitedSameRequestIsProcessedAfterQuotaRecovers() {
        String body = SignedRequestFactory.bodySha256("{\"retry\":true}");
        // 用满配额 5（填充请求各自带唯一 id 与递增序号/时间戳）
        for (int i = 1; i <= 5; i++) {
            GatewayRequest filler = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                    "retry-fill-" + i, now + i, (long) i, "POST", "/api/echo", body);
            assertTrue(gateway.evaluate(filler).allowed(), "配额内填充请求应放行");
        }

        // 目标请求：带固定 requestId=retry-X、seq=100，首次提交被限流
        GatewayRequest x = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "retry-X", now + 100, 100L, "POST", "/api/echo", body);
        assertRejected(gateway.evaluate(x), RejectionReason.RATE_LIMITED);
        log.info("重试判定依据: 首次提交 requestId=retry-X 因配额满被 RATE_LIMITED，不登记去重、不推进水位");

        // 被限流的请求不应留下任何重放痕迹：仍是 5 个填充请求占用的记录，X 未被登记
        assertEquals(5, replayProtector.trackedCount("alice"),
                "被限流的请求不得登记 requestId / 推进水位");

        // 配额恢复（窗口滚动）后，用“完全相同”的请求重试：必须放行，不能是 REPLAYED / SEQUENCE_REGRESSION
        rateLimiter.reset();
        GatewayDecision retried = gateway.evaluate(x);
        log.info("重试判定依据: 配额恢复后同一请求重试 -> allowed={}, reason={}",
                retried.allowed(), retried.reason());
        assertTrue(retried.allowed(), "重试必须被正常处理，不能因上次被拒而判重放/序号回退，实际=" + retried.reason());

        // 重试真正执行后，再提交一次同请求才应被判重放（证明去重在真正执行时才生效）
        assertRejected(gateway.evaluate(x), RejectionReason.REPLAYED_REQUEST);
        log.info("重试判定依据: 已执行过的同一请求再次提交 -> REPLAYED_REQUEST（去重仅对真正执行的请求生效）");
    }

    @Test
    @DisplayName("不占名额：鉴权失败（伪造签名）的请求不登记 requestId，随后同 id 的合法请求可放行")
    void authFailureDoesNotOccupyDedupSlot() {
        String body = SignedRequestFactory.bodySha256("{\"auth\":false}");
        GatewayRequest forged = SignedRequestFactory.withForgedSignature(
                SignedRequestFactory.signed(registry, "HMAC1", "alice",
                        "auth-slot-id", now + 1, 1L, "POST", "/api/echo", body));
        assertRejected(gateway.evaluate(forged), RejectionReason.SIGNATURE_MISMATCH);
        log.info("不占名额判定依据: 伪造签名被 SIGNATURE_MISMATCH 拒绝，不进入防重放状态");

        // 同一 requestId、时间戳、序号的“合法签名”请求应放行，不被误判重放/回退
        GatewayRequest legit = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "auth-slot-id", now + 1, 1L, "POST", "/api/echo", body);
        GatewayDecision d = gateway.evaluate(legit);
        assertTrue(d.allowed(), "鉴权失败不应占用去重名额，合法同 id 请求应放行，实际=" + d.reason());
    }

    @Test
    @DisplayName("不占额度：防重放拒绝会归还刚占用的配额，后续合法请求仍在配额内放行")
    void replayRejectionReturnsQuota() {
        String body = SignedRequestFactory.bodySha256("{\"q\":1}");
        // 先用掉 4/5，留一个配额给“先过限流、后被防重放拒绝”的请求
        for (int i = 1; i <= 4; i++) {
            assertTrue(gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "alice",
                    "q-fill-" + i, now + i, (long) i, "POST", "/api/echo", body)).allowed());
        }
        // q-fifth 首次放行（占第 5 个配额）；其重放会再占一个配额并在防重放环节被拒，该配额必须归还
        GatewayRequest fifth = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "q-fifth", now + 5, 5L, "POST", "/api/echo", body);
        assertTrue(gateway.evaluate(fifth).allowed());

        // 此刻配额恰好耗尽；直接重放会先被限流挡住。先归还一个额度，让重放走“过限流->防重放拒绝->归还”路径
        rateLimiter.release("alice");
        assertRejected(gateway.evaluate(fifth), RejectionReason.REPLAYED_REQUEST);
        log.info("归还额度判定依据: 重放请求通过限流占位后被 REPLAYED_REQUEST，占用的配额已归还");

        // 若未归还，这里会被 RATE_LIMITED；正确语义下应放行
        GatewayDecision another = gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "q-another", now + 6, 6L, "POST", "/api/echo", body));
        assertTrue(another.allowed(), "防重放拒绝归还额度后，后续合法请求应仍在配额内，实际=" + another.reason());
        assertRejected(gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "q-onemore", now + 7, 7L, "POST", "/api/echo", body)), RejectionReason.RATE_LIMITED);
    }

    @Test
    @DisplayName("原因稳定：配额已满时，窗口内的重复请求仍判 REPLAYED_REQUEST，不被限流原因盖掉")
    void duplicateStaysReplayedEvenWhenQuotaExhausted() {
        String body = SignedRequestFactory.bodySha256("{\"stable\":true}");
        // 用 5 个唯一请求打满配额（全部真正执行）
        GatewayRequest first = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "stable-1", now + 1, 1L, "POST", "/api/echo", body);
        assertTrue(gateway.evaluate(first).allowed());
        for (int i = 2; i <= 5; i++) {
            assertTrue(gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "alice",
                    "stable-" + i, now + i, (long) i, "POST", "/api/echo", body)).allowed());
        }
        // 此刻配额已耗尽：全新请求会被 RATE_LIMITED……
        assertRejected(gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "stable-fresh", now + 6, 6L, "POST", "/api/echo", body)), RejectionReason.RATE_LIMITED);
        // ……但“已处理过的同一请求”必须稳定判重放，重复提交多少次原因都不漂移
        for (int attempt = 1; attempt <= 3; attempt++) {
            assertRejected(gateway.evaluate(first), RejectionReason.REPLAYED_REQUEST);
        }
        log.info("原因稳定判定依据: 配额已满时，全新请求 -> RATE_LIMITED，已处理过的重复请求 -> REPLAYED_REQUEST（多次提交结论一致）");
    }

    @Test
    @DisplayName("并发交错：配额满时同 id 重试全部 RATE_LIMITED 且不留痕；配额恢复后并发重试恰好放行一次")
    void concurrentRateLimitRejectThenRetryAdmitsOnce() throws InterruptedException {
        String body = SignedRequestFactory.bodySha256("{\"race\":true}");
        for (int i = 1; i <= 5; i++) {
            assertTrue(gateway.evaluate(SignedRequestFactory.signed(registry, "HMAC1", "bob",
                    "race-fill-" + i, now + i, (long) i, "POST", "/api/echo", body)).allowed());
        }
        GatewayRequest x = SignedRequestFactory.signed(registry, "HMAC1", "bob",
                "race-X", now + 50, 50L, "POST", "/api/echo", body);

        int n = 24;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        AtomicInteger rateLimited = new AtomicInteger();
        ConcurrentLinkedQueue<RejectionReason> others = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    GatewayDecision d = gateway.evaluate(x); // 阶段一：配额已满
                    if (!d.allowed() && d.reason() == RejectionReason.RATE_LIMITED) {
                        rateLimited.incrementAndGet();
                    } else if (!d.allowed()) {
                        others.add(d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdownNow();
        log.info("并发交错阶段一: 并发数={}, RATE_LIMITED={}, 其他拒绝={}（限流拒绝不得污染重放状态）",
                n, rateLimited.get(), others.size());
        assertEquals(n, rateLimited.get(), "配额已满时所有并发重试都必须 RATE_LIMITED");
        assertTrue(others.isEmpty(), "不能出现重放/序号回退等其他拒绝: " + others);

        // 阶段二：配额恢复，同 id 高并发重试——恰好一次放行，其余 REPLAYED_REQUEST（该拒的拒、该放的放）。
        // 隔离压测“恢复后的重放交错”：把配额抬到并发数以上，排除阶段二再次命中限流。
        int m = 32;
        long originalQuota = properties.getQuotaPerWindow();
        properties.setQuotaPerWindow(m + 10L);
        rateLimiter.reset();
        try {
            ExecutorService pool2 = Executors.newFixedThreadPool(m);
            CountDownLatch start2 = new CountDownLatch(1);
            CountDownLatch done2 = new CountDownLatch(m);
            AtomicInteger allowed = new AtomicInteger();
            AtomicInteger replayed = new AtomicInteger();
            for (int i = 0; i < m; i++) {
                pool2.submit(() -> {
                    try {
                        start2.await();
                        GatewayDecision d = gateway.evaluate(x);
                        if (d.allowed()) {
                            allowed.incrementAndGet();
                        } else if (d.reason() == RejectionReason.REPLAYED_REQUEST) {
                            replayed.incrementAndGet();
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
            assertTrue(done2.await(30, TimeUnit.SECONDS));
            pool2.shutdownNow();
            log.info("并发交错阶段二: 配额恢复后并发数={}, 放行={}, REPLAYED_REQUEST={}, 其他拒绝={}",
                    m, allowed.get(), replayed.get(), others.size());
            assertEquals(1, allowed.get(), "配额恢复后同一请求并发重试只能真正执行一次");
            assertEquals(m - 1, replayed.get(), "其余并发重试必须识别为窗口内重放");
            assertTrue(others.isEmpty(), "不应出现限流等其他拒绝: " + others);
        } finally {
            properties.setQuotaPerWindow(originalQuota);
            rateLimiter.reset();
        }
    }
}
