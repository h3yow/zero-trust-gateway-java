package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayDecision;
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
    }
}
