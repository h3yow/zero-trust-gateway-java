package com.github.h3yow.zerotrustgatewayjava.engine;

import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;

/**
 * 零信任判定主流程：鉴权 -> 时间窗口 -> 限流 -> 重放/序号。
 */
public interface DecisionEngine {
    Decision evaluate(RequestContext request);
}
