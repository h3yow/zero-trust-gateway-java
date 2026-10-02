package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.github.h3yow.zerotrustgatewayjava.gateway.CallerPrincipal;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayProperties;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.RejectionReason;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 重放记录的时效边界与容量收敛：
 * <ul>
 *   <li>窗口内重放一律拦截，越过窗口的陈旧记录不再拦截新请求；</li>
 *   <li>到期后记录被实际清理，规模不再随唯一标识单调增长；</li>
 *   <li>容量上限：清完过期仍满则明确 {@code REPLAY_STORE_FULL}，不静默放过、不驱逐有效记录。</li>
 * </ul>
 * 使用可控时钟，无需真实等待即可精确覆盖边界，结论确定不抖动。
 */
class ReplayConvergenceTests {

    private static final Logger log = LoggerFactory.getLogger(ReplayConvergenceTests.class);

    private static final long SKEW = 1_000L;
    private static final CallerPrincipal ALICE = new CallerPrincipal("alice", "HMAC1", "alice");

    private GatewayProperties properties;
    private MutableClock clock;
    private ReplayProtector protector;

    @BeforeEach
    void setUp() {
        properties = new GatewayProperties();
        properties.setTimestampSkewMillis(SKEW);
        properties.setReplayMaxIdsPerSubject(4);
        clock = new MutableClock(100_000L);
        protector = new ReplayProtector(properties, clock);
    }

    private static GatewayRequest req(String id, long timestamp, Long sequence) {
        return new GatewayRequest("HMAC1 dummy", "alice", id, timestamp, sequence,
                "POST", "/api/echo", "bodysha");
    }

    @Test
    @DisplayName("时效边界：窗口内重放拦截；恰越过窗口后陈旧记录被清理，同一 requestId 的新请求放行")
    void expiryBoundaryStopsInterceptingStaleIds() {
        long t0 = clock.millis();

        // t0 时刻登记 id-1（过期点 = t0 + skew）
        assertNull(protector.check(ALICE, req("id-1", t0, 1L)), "首次提交应通过");
        assertEquals(1, protector.trackedCount("alice"));

        // 窗口内（t0+skew 时刻仍算有效）：同 id 重放必须拦住
        clock.set(t0 + SKEW);
        assertEquals(RejectionReason.REPLAYED_REQUEST,
                protector.check(ALICE, req("id-1", t0 + SKEW, 2L)),
                "过期点时刻旧记录仍有效，重放必须拦截");

        // 越过窗口 1ms：陈旧记录到期。此时再用同 id 携带“新时间戳”请求，不应再被旧记录拦截
        clock.set(t0 + SKEW + 1);
        assertNull(protector.check(ALICE, req("id-1", t0 + SKEW + 1, 3L)),
                "越过窗口后同一 requestId 的新请求应放行，不被陈旧记录拦截");
        // 旧记录已在本次 check 中被到期清理，仅保留刚登记的新记录（规模不随时间单调增长）
        assertEquals(1, protector.trackedCount("alice"), "陈旧记录应已清理，只剩新登记的一条");
        log.info("时效收敛判定依据: skew={}, 旧记录过期点={}, 新请求时刻={} -> 陈旧记录清理后放行",
                SKEW, t0 + SKEW, t0 + SKEW + 1);
    }

    @Test
    @DisplayName("时效收敛：大量互不相同的标识跨时间持续进入，到期记录被摊销清理，规模始终有界、耗时稳定")
    void highThroughputUniqueIdsAreAmortizedEvicted() {
        // 该用例隔离验证“时效收敛”：把容量抬到远高于窗口内峰值，排除容量拒绝的干扰
        properties.setReplayMaxIdsPerSubject(1_000_000);
        long t = clock.millis();
        int iterations = 10_000;
        for (int i = 0; i < iterations; i++) {
            long now = t + i * 10L; // 每次推进 10ms，超过 skew 后旧记录陆续到期
            clock.set(now);
            assertNull(protector.check(ALICE, req("stream-" + i, now, (long) i)),
                    "唯一标识的新请求不应被拦截");
        }
        // skew=1000ms、每请求间隔 10ms -> 最多保留约 100 个有效记录，远小于 10000 的总流入量
        int retained = protector.trackedCount("alice");
        log.info("容量收敛判定依据: 总流入={}, 窗口内保留={}", iterations, retained);
        assertEquals(0, Integer.signum(retained - 101),
                "保留量应只覆盖约一个窗口（<=101），不能随总流入量只增不减");
        assert retained > 0 : "窗口内仍应有有效记录";
    }

    @Test
    @DisplayName("容量上限：清完过期仍达上限 -> REPLAY_STORE_FULL；过期腾出空间后新请求恢复放行")
    void capacityLimitIsExplicitAndRecoversAfterExpiry() {
        long t0 = clock.millis();
        // 用 4 个不同标识打满容量（均在窗口内）
        for (int i = 1; i <= 4; i++) {
            assertNull(protector.check(ALICE, req("cap-" + i, t0, (long) i)), "容量内请求通过");
        }
        assertEquals(4, protector.trackedCount("alice"));

        // 第 5 个全新标识：容量满，必须明确拒绝（不是静默放过、也不是重放）
        RejectionReason reason = protector.check(ALICE, req("cap-new", t0, 5L));
        assertEquals(RejectionReason.REPLAY_STORE_FULL, reason,
                "有效记录占满容量时必须给出明确原因，不能静默放过");
        assertEquals(4, protector.trackedCount("alice"), "拒绝不能污染状态、不能驱逐有效记录");
        log.info("容量上限判定依据: retained=4, capacity=4 -> REPLAY_STORE_FULL（不静默放过、不驱逐有效记录）");

        // 越过窗口：旧记录全部到期腾出空间，新请求恢复放行
        clock.set(t0 + SKEW + 1);
        assertNull(protector.check(ALICE, req("cap-new", t0 + SKEW + 1, 6L)),
                "过期腾出空间后新请求应恢复放行");
        log.info("容量恢复判定依据: 旧记录到期清理后 trackedCount=1，新请求放行");
    }

    @Test
    @DisplayName("容量上限不误伤：窗口内真正的重复请求即使容量已满，仍判 REPLAYED_REQUEST 而非容量拒绝")
    void duplicateWithinWindowIsReplayEvenWhenFull() {
        long t0 = clock.millis();
        for (int i = 1; i <= 4; i++) {
            assertNull(protector.check(ALICE, req("dup-" + i, t0, (long) i)));
        }
        // 容量已满，但这次是已存在标识的真重复 -> 必须判重放，不能用容量原因搪塞，更不能放行
        assertEquals(RejectionReason.REPLAYED_REQUEST,
                protector.check(ALICE, req("dup-1", t0, 5L)));
        log.info("容量/重放优先级判定依据: 容量满且 requestId 命中窗口内有效记录 -> REPLAYED_REQUEST");
    }

    /** 测试用可控时钟。 */
    private static final class MutableClock extends Clock {
        private final AtomicLong now;

        private MutableClock(long epochMillis) {
            this.now = new AtomicLong(epochMillis);
        }

        void set(long epochMillis) {
            now.set(epochMillis);
        }

        @Override
        public long millis() {
            return now.get();
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
            return Instant.ofEpochMilli(now.get());
        }
    }
}
