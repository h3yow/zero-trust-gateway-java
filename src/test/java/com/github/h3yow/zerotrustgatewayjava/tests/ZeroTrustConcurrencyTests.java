package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * 高并发/竞态测试：实际放行量不得超过配额；同一请求并发重放只能有一次成功。
 */
@SpringBootTest
class ZeroTrustConcurrencyTests {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustConcurrencyTests.class);

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

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
    }

    @Test
    @DisplayName("并发限流：50 个线程同时突发，配额 5 内恰好放行 5 个，其余全部 RATE_LIMITED")
    void concurrentBurstNeverExceedsQuota() throws InterruptedException {
        int threads = 50;
        int quota = 5;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        ConcurrentLinkedQueue<RejectionReason> rejects = new ConcurrentLinkedQueue<>();

        long now = System.currentTimeMillis();
        String bodySha = SignedRequestFactory.bodySha256("{\"burst\":true}");
        for (int i = 0; i < threads; i++) {
            long seq = i + 1;
            pool.submit(() -> {
                try {
                    start.await();
                    // 相同时间戳、不带序号、唯一 requestId：排除乱序导致的序号回退，
                    // 纯粹压测限流在并发下“配额不超、计数不丢”的竞态语义。
                    GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                            "burst-" + seq, now, null, "POST", "/api/echo", bodySha);
                    GatewayDecision d = gateway.evaluate(r);
                    if (d.allowed()) {
                        allowed.incrementAndGet();
                    } else {
                        rejects.add(d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发用例应在超时前完成");
        pool.shutdownNow();

        long rateLimited = rejects.stream().filter(x -> x == RejectionReason.RATE_LIMITED).count();
        log.info("并发限流结果: 总线程={}, 放行={}, RATE_LIMITED={}, 其他拒绝={}",
                threads, allowed.get(), rateLimited, rejects.size() - rateLimited);
        assertEquals(quota, allowed.get(), "并发下实际放行量必须恰好等于配额，不能多也不能计数丢失");
        assertEquals(threads - quota, rateLimited, "超出配额的请求必须全部因 RATE_LIMITED 被拒绝");
    }

    @Test
    @DisplayName("并发重放：同一请求被 32 个线程同时提交，恰好 1 次放行，其余全部 REPLAYED_REQUEST")
    void concurrentReplayAdmitsExactlyOnce() throws InterruptedException {
        int threads = 32;
        long now = System.currentTimeMillis();
        GatewayRequest shared = SignedRequestFactory.signed(registry, "HMAC2", "bob",
                "replay-once", now, 1L, "POST", "/api/echo", SignedRequestFactory.bodySha256("{}"));

        // 该用例隔离压测防重放：临时把 bob/共享窗口配额抬到线程数以上，避免限流与重放原因交错，
        // 用后恢复；限流与重放交错的语义在 RetryAfterRejectionTests 中专门覆盖。
        long originalQuota = properties.getQuotaPerWindow();
        properties.setQuotaPerWindow(threads + 10L);
        rateLimiter.reset();
        try {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(threads);
            AtomicInteger allowed = new AtomicInteger();
            AtomicInteger replayed = new AtomicInteger();

            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        GatewayDecision d = gateway.evaluate(shared);
                        if (d.allowed()) {
                            allowed.incrementAndGet();
                        } else if (d.reason() == RejectionReason.REPLAYED_REQUEST) {
                            replayed.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS), "并发用例应在超时前完成");
            pool.shutdownNow();

            log.info("并发重放结果: 总线程={}, 放行={}, REPLAYED_REQUEST={}",
                    threads, allowed.get(), replayed.get());
            assertEquals(1, allowed.get(), "同一 requestId 在并发下只能放行一次");
            assertEquals(threads - 1, replayed.get(), "其余并发请求必须全部识别为重放");
        } finally {
            properties.setQuotaPerWindow(originalQuota);
            rateLimiter.reset();
        }
    }

    @Test
    @DisplayName("混合突发：全新请求与大量“已处理过的重复请求”同时涌入——全新全部放行、重复全部判重放、放行不超配额")
    void mixedBurstOfFreshAndDuplicateRequests() throws InterruptedException {
        // 使用默认配额（quota-per-window=5），不调高：重复请求必须完全不占配额，
        // 全新请求在配额内必须全部放行，任何“重复挤占配额”或“重复被误判超限”都会使断言失败。
        int quota = (int) properties.getQuotaPerWindow();
        int dupThreads = 64;
        long now = System.currentTimeMillis();
        String bodySha = SignedRequestFactory.bodySha256("{\"mixed\":true}");

        // 种子请求：先正常处理一次（占 1 个配额、登记 requestId），之后它的副本都是“窗口内重复”
        GatewayRequest seed = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "mixed-seed", now, null, "POST", "/api/echo", bodySha);
        GatewayDecision seedDecision = gateway.evaluate(seed);
        assertTrue(seedDecision.allowed(), "种子请求首次提交应放行，实际=" + seedDecision.reason());
        log.info("混合突发判定依据: 种子请求 requestId=mixed-seed 已放行并登记，占用配额 1/{}", quota);

        // 突发：quota-1 个全新请求（凑满配额）+ 64 个种子请求的重复副本，同时放行闸门
        int freshThreads = quota - 1;
        int total = freshThreads + dupThreads;
        ExecutorService pool = Executors.newFixedThreadPool(total);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(total);
        AtomicInteger freshAllowed = new AtomicInteger();
        AtomicInteger dupReplayed = new AtomicInteger();
        ConcurrentLinkedQueue<String> unexpected = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < freshThreads; i++) {
            String requestId = "mixed-fresh-" + i;
            pool.submit(() -> {
                try {
                    start.await();
                    // 相同时间戳、不带序号、唯一 requestId：排除序号回退干扰，纯粹压测准入语义
                    GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                            requestId, now, null, "POST", "/api/echo", bodySha);
                    GatewayDecision d = gateway.evaluate(r);
                    if (d.allowed()) {
                        freshAllowed.incrementAndGet();
                    } else {
                        unexpected.add("fresh " + requestId + " -> " + d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        for (int i = 0; i < dupThreads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    GatewayDecision d = gateway.evaluate(seed); // 已处理过的同一请求
                    if (!d.allowed() && d.reason() == RejectionReason.REPLAYED_REQUEST) {
                        dupReplayed.incrementAndGet();
                    } else {
                        unexpected.add("dup -> allowed=" + d.allowed() + ", reason=" + d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发用例应在超时前完成");
        pool.shutdownNow();

        log.info("混合突发结果: 全新请求={} 放行={}, 重复副本={} 判重放={}, 意外结果={}",
                freshThreads, freshAllowed.get(), dupThreads, dupReplayed.get(), unexpected);
        assertTrue(unexpected.isEmpty(),
                "全新请求不得被超限/其他原因拒绝，重复副本不得出现重放以外的原因: " + unexpected);
        assertEquals(freshThreads, freshAllowed.get(),
                "配额之内的全新请求必须全部放行，不能被同时涌入的重复请求挤成超限");
        assertEquals(dupThreads, dupReplayed.get(),
                "已处理过的重复请求必须全部稳定判 REPLAYED_REQUEST，即使配额被打满");
        int totalAllowed = 1 + freshAllowed.get(); // 种子 + 突发期放行
        assertTrue(totalAllowed <= quota, "窗口内实际放行总数不得超过配额: " + totalAllowed + " > " + quota);
        log.info("混合突发放行上限核对: 窗口内实际放行总数={} <= 配额={}", totalAllowed, quota);
    }
}
