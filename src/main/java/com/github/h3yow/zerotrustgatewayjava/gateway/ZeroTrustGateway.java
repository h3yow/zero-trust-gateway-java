package com.github.h3yow.zerotrustgatewayjava.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 判定编排。顺序与状态语义：
 * <pre>
 * 必备头结构检查 -> 鉴权(AuthenticationService，含服务端生命周期)
 *   -> 防重放/防篡改检查(ReplayProtector.check，只读不留痕)
 *   -> 限流占额(RateLimiter.tryAcquire)
 *   -> 去重登记(ReplayProtector.commit) -> 业务处理
 * </pre>
 *
 * <p><b>被拒之后可安全重试</b>：鉴权失败、防重放拒绝发生在限流占额之前；限流拒绝
 * 发生在去重登记之前。三种拒绝都既不消耗去重名额，也不推进主体序号水位，也不
 * 真正计费。因此调用方配额恢复后拿同一请求（同一 requestId 与序号）重试可以被
 * 正常处理，而不会被当成重复请求或序号回退。
 *
 * <p>限流与去重登记分离时，占额后若在提交阶段被并发抢先（极端竞态），会原样
 * {@code release} 退还配额，保证“只有真正放行的请求计费”的最终语义不变。
 * 输入要素与判定依据都会记录到日志，同一输入在状态一致时结论稳定可复现。
 */
@Component
public class ZeroTrustGateway {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustGateway.class);

    private final AuthenticationService authenticationService;
    private final ReplayProtector replayProtector;
    private final RateLimiter rateLimiter;

    public ZeroTrustGateway(AuthenticationService authenticationService,
                            ReplayProtector replayProtector,
                            RateLimiter rateLimiter) {
        this.authenticationService = authenticationService;
        this.replayProtector = replayProtector;
        this.rateLimiter = rateLimiter;
    }

    public GatewayDecision evaluate(GatewayRequest request) {
        log.info("收到判定输入: claimedSubject={}, requestId={}, timestamp={}, sequence={}, {} {}",
                request.claimedSubject(), request.requestId(), request.timestamp(), request.sequence(),
                request.method(), request.path());

        // 0) 必备要素：凭证头缺失最先判定；requestId/timestamp 缺失次之，
        //    这样“要素缺失”不会被后续的签名不符掩盖，原因始终可区分。
        if (request.credentialHeader() == null || request.credentialHeader().isBlank()) {
            log.info("判定依据: 鉴权拒绝 reason={}", RejectionReason.MISSING_CREDENTIAL);
            return GatewayDecision.reject(RejectionReason.MISSING_CREDENTIAL, "请求未携带凭证头");
        }
        if (request.requestId() == null || request.requestId().isBlank()) {
            log.info("判定依据: 防重放要素缺失 reason={}", RejectionReason.MISSING_REQUEST_ID);
            return GatewayDecision.reject(RejectionReason.MISSING_REQUEST_ID, "请求缺少唯一标识头 X-Request-Id");
        }
        if (request.timestamp() == null) {
            log.info("判定依据: 防重放要素缺失 reason={}", RejectionReason.MISSING_TIMESTAMP);
            return GatewayDecision.reject(RejectionReason.MISSING_TIMESTAMP, "请求缺少时间戳头 X-Timestamp");
        }

        // 1) 鉴权（含服务端凭证生命周期：未生效/已失效/已撤销，两类凭证版本同一判定）
        CallerPrincipal principal;
        try {
            principal = authenticationService.authenticate(request);
        } catch (CredentialRejectedException e) {
            log.info("判定依据: 鉴权拒绝 reason={}, detail={}", e.getReason(), e.getMessage());
            return GatewayDecision.reject(e.getReason(), e.getMessage());
        }
        log.info("判定依据: 鉴权通过 principal={}/{} via {}",
                principal.subjectId(), principal.credentialId(), principal.credentialType());

        // 2) 防重放/防篡改：只读检查，不登记、不推进水位；被拒请求可在条件变化后原样重试
        RejectionReason replayReason = replayProtector.check(principal, request);
        if (replayReason != null) {
            log.info("判定依据: 防重放拒绝 reason={}, subject={}, requestId={}",
                    replayReason, principal.subjectId(), request.requestId());
            return GatewayDecision.reject(replayReason,
                    "请求未通过防重放/防篡改校验: " + replayReason);
        }

        // 3) 限流：占额失败直接拒绝，此时尚未登记去重信息，重试不被误判
        if (!rateLimiter.tryAcquire(principal.subjectId())) {
            log.info("判定依据: 限流拒绝 reason={}, subject={}（未登记去重，可在配额恢复后重试）",
                    RejectionReason.RATE_LIMITED, principal.subjectId());
            return GatewayDecision.reject(RejectionReason.RATE_LIMITED,
                    "主体 " + principal.subjectId() + " 已超出当前窗口配额");
        }

        // 4) 去重登记：极端并发下可能在此处被抢先提交，失败必须退还刚占用的配额
        RejectionReason commitReason = replayProtector.commit(principal, request);
        if (commitReason != null) {
            rateLimiter.release(principal.subjectId());
            log.info("判定依据: 提交阶段防重放拒绝 reason={}, subject={}, requestId={}（已退还配额）",
                    commitReason, principal.subjectId(), request.requestId());
            return GatewayDecision.reject(commitReason,
                    "请求未通过防重放/防篡改校验: " + commitReason);
        }

        log.info("判定依据: 放行 subject={}, requestId={}", principal.subjectId(), request.requestId());
        return GatewayDecision.allow(principal);
    }
}
