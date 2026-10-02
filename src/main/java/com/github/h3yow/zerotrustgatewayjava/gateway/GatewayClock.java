package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.time.Clock;
import org.springframework.stereotype.Component;

/**
 * 网关统一时钟：生产环境取系统 UTC 时钟；测试可替换为固定/偏移时钟，
 * 以便确定性地验证时间窗口、重放记录时效与限流窗口滚动，无需真实 sleep。
 */
@Component
public class GatewayClock {

    private volatile Clock clock = Clock.systemUTC();

    public long nowMillis() {
        return clock.millis();
    }

    /** 仅供测试：替换底层时钟。 */
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    /** 仅供测试：恢复系统时钟。 */
    public void reset() {
        this.clock = Clock.systemUTC();
    }
}
