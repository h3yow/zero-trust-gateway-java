package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
 * 重放记录按时效与容量收敛测试：
 * 窗口内重放必拦、越过窗口的陈旧记录不再拦截新请求、记录数只减不增地收敛、
 * 容量上限 fail-closed（明确拒绝而非静默放过，且不驱逐有效期内记录）。
 * 使用 {@link GatewayClock} 确定性推进时间，不依赖真实 sleep。
 */
@SpringBootTest
@TestPropertySource(properties = {
        "zero-trust.gateway.quota-per-window=100000",
        "zero-trust.gateway.window-millis=3600000",
        "zero-trust.gateway.timestamp-skew-millis=1000",
        "zero-trust.gateway.replay-max-records-per-subject=50"
})
class ReplayConvergenceTests {

    private static final Logger log = LoggerFactory.getLogger(ReplayConvergenceTests.class);

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
        gatewayClock.reset();
        seq = 0;
    }

    @AfterEach
    void restoreClock() {
        gatewayClock.reset();
    }

    /** 在指定“当前时间”发起一个已签名请求；请求时间戳取当前时间，保证通过时间窗。 */
    private GatewayRequest at(String subject, String requestId, Instant now) {
        gatewayClock.setClock(Clock.fixed(now, ZoneOffset.UTC));
        return SignedRequestFactory.signed(registry, "HMAC1", subject, subject,
                requestId, now.toEpochMilli(), ++seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), now.toEpochMilli() + 600_000, null);
    }

    private void assertRejected(GatewayDecision d, RejectionReason expected) {
        log.info("时效/容量用例断言: 期望拒绝={}, 实际 allowed={}, reason={}, message={}",
                expected, d.allowed(), d.reason(), d.message());
        assertFalse(d.allowed());
        assertEquals(expected, d.reason());
        assertNotNull(d.message());
    }

    @Test
    @DisplayName("时效边界：窗口内同 requestId 立刻重放仍拦截（REPLAYED_REQUEST）")
    void replayWithinWindowIsRejected() {
        Instant now = t0;
        GatewayRequest r = at("alice", "id-win", now);
        assertTrue(gateway.evaluate(r).allowed());
        // 仍在 skew=1000ms 窗口内（记录过期时刻 = ts + 1000）
        assertRejected(gateway.evaluate(at("alice", "id-win", now.plusMillis(999))),
                RejectionReason.REPLAYED_REQUEST);
    }

    @Test
    @DisplayName("时效边界（精确到毫秒）：到期前一刻仍拦截；越过窗口后新请求复用旧 requestId 立即放行")
    void expiryBoundaryIsExactToTheMillisecond() {
        String requestId = "id-boundary";
        // 固定一条 ts=t0、不带序号的请求（其记录到期时刻 = t0 + skew = t0+1000；
        // 不带序号可排除水位回退干扰，纯粹验证 requestId 记录的时效边界）。
        GatewayRequest first = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                requestId, t0.toEpochMilli(), null, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), t0.toEpochMilli() + 600_000, null);
        gatewayClock.setClock(Clock.fixed(t0, ZoneOffset.UTC));
        assertTrue(gateway.evaluate(first).allowed());

        // 到期前 1ms：仍在窗口内 → 必须拦截
        gatewayClock.setClock(Clock.fixed(t0.plusMillis(999), ZoneOffset.UTC));
        assertRejected(gateway.evaluate(first), RejectionReason.REPLAYED_REQUEST);

        // 到期当刻（now = t0+1000；到期条件为 expiry < now，此刻尚未严格过期）→ 仍拦截
        gatewayClock.setClock(Clock.fixed(t0.plusMillis(1000), ZoneOffset.UTC));
        assertRejected(gateway.evaluate(first), RejectionReason.REPLAYED_REQUEST);

        // 越过 1ms（now = t0+1001）：旧记录已到期回收。
        // 新请求用当前时间戳签名（真实调用方行为），但复用同一个 requestId —— 必须放行。
        GatewayRequest freshWithSameId = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                requestId, t0.plusMillis(1001).toEpochMilli(), null, "POST", "/api/echo",
                SignedRequestFactory.bodySha256("{}"), t0.plusMillis(1001).toEpochMilli() + 600_000, null);
        gatewayClock.setClock(Clock.fixed(t0.plusMillis(1001), ZoneOffset.UTC));
        assertTrue(gateway.evaluate(freshWithSameId).allowed(),
                "陈旧记录到期后，同 requestId 的新请求必须立即放行，不能再被旧记录拦截");
    }

    @Test
    @DisplayName("时效边界：恰好越过窗口后，陈旧记录不再拦截同一 requestId 的新请求")
    void staleRecordBeyondWindowIsReusable() {
        GatewayRequest first = at("alice", "id-expiry", t0);
        assertTrue(gateway.evaluate(first).allowed());
        assertEquals(1, replayProtector.activeRecordCount("alice"));

        // 越过窗口边界（过期时刻 = ts + 1000，严格小于才过期；1001ms 后必过期）
        Instant later = t0.plusMillis(1001);
        GatewayRequest retried = at("alice", "id-expiry", later);
        GatewayDecision d = gateway.evaluate(retried);
        log.info("越过窗口后重提同一 requestId: allowed={}, reason={}", d.allowed(), d.reason());
        assertTrue(d.allowed(), "越过时间窗口后，陈旧记录必须已收敛，不能再拦截新请求");
        assertEquals(1, replayProtector.activeRecordCount("alice"),
                "陈旧记录应被回收，新记录顶替，规模不增长");
    }

    @Test
    @DisplayName("容量收敛：持续涌入大量互不相同的 requestId，陈旧记录被回收，规模稳定在上限内")
    void highThroughputRecordCountConverges() {
        int total = 500; // 上限为 50 的 10 倍
        int observedMax = 0;
        for (int i = 0; i < total; i++) {
            // 每 20 个请求把时间推进 1050ms（> skew=1000）：
            // 这样在记录数逼近上限 50（即第 3 批进行中）时，第 1 批恰好整批过期，
            // 回收出确定的空间，容量保护永不误触发，同时记录规模持续按时效收敛。
            Instant now = t0.plusMillis((long) (i / 20) * 1050L);
            GatewayRequest r = at("bob", "bulk-" + i, now);
            GatewayDecision d = gateway.evaluate(r);
            assertTrue(d.allowed(), "存在过期空间时高吞吐请求不应被容量保护拒绝, i=" + i
                    + ", reason=" + d.reason());
            observedMax = Math.max(observedMax, replayProtector.activeRecordCount("bob"));
        }
        int finalCount = replayProtector.activeRecordCount("bob");
        log.info("高吞吐收敛结果: 总请求={}, 观测峰值记录={}, 最终有效记录={}, 上限=50",
                total, observedMax, finalCount);
        assertTrue(observedMax <= 50, "有效记录数任何时刻都不能超过上限，观测峰值=" + observedMax);
        assertTrue(finalCount < total, "记录规模必须按时效收敛，而不是只增不减");
        assertEquals(20, finalCount, "最后一个时间批次（20 个）应在窗口内保留");
    }

    @Test
    @DisplayName("容量上限 fail-closed：窗口内打满 50 条后，第 51 个明确 REPLAY_CAPACITY_EXCEEDED，不静默放过")
    void capacityLimitFailsClosed() {
        for (int i = 0; i < 50; i++) {
            GatewayRequest r = at("alice", "cap-" + i, t0.plusMillis(i));
            assertTrue(gateway.evaluate(r).allowed(), "上限内第 " + i + " 个应放行");
        }
        assertEquals(50, replayProtector.activeRecordCount("alice"));

        GatewayRequest overflow = at("alice", "cap-overflow", t0.plusMillis(50));
        GatewayDecision d = gateway.evaluate(overflow);
        log.info("容量上限结果: allowed={}, reason={}, message={}", d.allowed(), d.reason(), d.message());
        assertRejected(d, RejectionReason.REPLAY_CAPACITY_EXCEEDED);
    }

    @Test
    @DisplayName("容量上限不误伤：打满后只要时间推进使旧记录过期，新请求立即恢复放行")
    void capacityRecoversAfterExpiry() {
        for (int i = 0; i < 50; i++) {
            assertTrue(gateway.evaluate(at("alice", "rec-" + i, t0.plusMillis(i))).allowed());
        }
        assertRejected(gateway.evaluate(at("alice", "rec-blocked", t0.plusMillis(50))),
                RejectionReason.REPLAY_CAPACITY_EXCEEDED);

        // 时间越过整个窗口：全部 50 条陈旧记录被回收
        Instant later = t0.plusMillis(2500);
        assertTrue(gateway.evaluate(at("alice", "rec-after-expiry", later)).allowed());
        assertEquals(1, replayProtector.activeRecordCount("alice"));
    }

    @Test
    @DisplayName("容量保护不驱逐有效期内记录：满容量时的重复请求仍判 REPLAYED_REQUEST 而非容量原因")
    void liveReplayDetectedEvenWhenFull() {
        for (int i = 0; i < 50; i++) {
            assertTrue(gateway.evaluate(at("alice", "live-" + i, t0.plusMillis(i))).allowed());
        }
        // 窗口内重放其中一条已登记的 ID：必须识别为重复，不能被容量原因掩盖，更不能放行
        assertRejected(gateway.evaluate(at("alice", "live-7", t0.plusMillis(50))),
                RejectionReason.REPLAYED_REQUEST);
    }
}
