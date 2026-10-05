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
import java.util.concurrent.ConcurrentHashMap;
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
    @DisplayName("混合突发：全新请求与大量“已处理过的同一重复请求”同时到达，全新全部放行、重复全部判重放、放行不超配额")
    void mixedBurstFreshAllowedDuplicatesReplayedWithinQuota() throws InterruptedException {
        String body = SignedRequestFactory.bodySha256("{\"mix\":true}");
        long now = System.currentTimeMillis();
        int quota = (int) properties.getQuotaPerWindow(); // application.properties: 5，保持原样不抬高

        // 前置：先处理掉一个请求 mix-done，制造“已处理过的同一重复请求”；
        // 随后仅恢复配额（模拟窗口滚动），去重记录保留——重复判定与配额余量从此刻起解耦。
        GatewayRequest done = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                "mix-done", now, null, "POST", "/api/echo", body);
        GatewayDecision first = gateway.evaluate(done);
        assertTrue(first.allowed(), "前置请求应放行，实际=" + first.reason());
        rateLimiter.reset();
        log.info("混合突发判定依据: 前置请求 mix-done 已执行并登记去重；配额已恢复为 {}", quota);

        // 突发：quota 个全新请求 + 大量 mix-done 的重复提交，同时放行
        int freshCount = quota;
        int dupCount = 60;
        int threads = freshCount + dupCount;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);
        ConcurrentHashMap<String, GatewayDecision> freshResults = new ConcurrentHashMap<>();
        ConcurrentLinkedQueue<RejectionReason> dupRejects = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<GatewayDecision> unexpected = new ConcurrentLinkedQueue<>();

        for (int i = 1; i <= freshCount; i++) {
            String freshId = "mix-fresh-" + i;
            pool.submit(() -> {
                try {
                    start.await();
                    // 相同时间戳、不带序号、唯一 requestId：排除序号回退干扰，纯压限流/重放交错
                    GatewayRequest r = SignedRequestFactory.signed(registry, "HMAC1", "alice",
                            freshId, now, null, "POST", "/api/echo", body);
                    freshResults.put(freshId, gateway.evaluate(r));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }
        for (int i = 0; i < dupCount; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    GatewayDecision d = gateway.evaluate(done);
                    if (d.allowed()) {
                        unexpected.add(d);
                    } else {
                        dupRejects.add(d.reason());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(doneLatch.await(30, TimeUnit.SECONDS), "并发用例应在超时前完成");
        pool.shutdownNow();

        long freshAllowed = freshResults.values().stream().filter(GatewayDecision::allowed).count();
        long freshRejected = freshCount - freshAllowed;
        long dupReplayed = dupRejects.stream().filter(r -> r == RejectionReason.REPLAYED_REQUEST).count();
        long dupRateLimited = dupRejects.stream().filter(r -> r == RejectionReason.RATE_LIMITED).count();
        log.info("混合突发结果: 全新请求={} (放行={}, 被拒={}), 重复请求={} (REPLAYED={}, RATE_LIMITED={}, 其他={}), 异常放行={}",
                freshCount, freshAllowed, freshRejected,
                dupCount, dupReplayed, dupRateLimited, dupRejects.size() - dupReplayed - dupRateLimited,
                unexpected.size());

        // 1) 重复请求全部稳定判 REPLAYED_REQUEST：即使与全新请求争抢、配额被打满，
        //    也不能出现 RATE_LIMITED 或原因抖动，更不能被放行
        assertEquals(dupCount, dupReplayed,
                "已处理过的重复请求必须全部判 REPLAYED_REQUEST，实际分布: " + dupRejects);
        assertTrue(unexpected.isEmpty(), "重复请求绝不能被放行: " + unexpected);
        // 2) 全新请求全部放行：在配额之内且无窗口内重复，不能被同时涌入的重复请求牵连成超限
        freshResults.forEach((id, d) -> assertTrue(d.allowed(),
                "全新请求 " + id + " 在配额之内必须放行，实际=" + d.reason()));
        // 3) 实际上限量守恒：放行数恰好等于全新请求数，且不超过配额
        assertEquals(freshCount, freshAllowed, "放行数应恰好等于全新请求数");
        assertTrue(freshAllowed <= quota, "实际放行数不能超过配额");
    }
}
