package com.github.h3yow.zerotrustgatewayjava.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 判定编排，三步固定顺序，每一步的拒绝原因彼此可区分：
 * <pre>鉴权(AuthenticationService) -> 防重放/防篡改(ReplayProtector) -> 限流(RateLimiter)</pre>
 * 同一输入在状态一致时结论稳定可复现；输入要素与判定依据都会记录到日志。
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

        // 1) 鉴权：失败原因（缺失/类型/格式/签名/过期/主体不一致）直接终止。
        //    凭证头本身的缺失最先判定；requestId/timestamp 等防重放必备头的缺失次之，
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

        CallerPrincipal principal;
        try {
            principal = authenticationService.authenticate(request);
        } catch (CredentialRejectedException e) {
            log.info("判定依据: 鉴权拒绝 reason={}, detail={}", e.getReason(), e.getMessage());
            return GatewayDecision.reject(e.getReason(), e.getMessage());
        }
        log.info("判定依据: 鉴权通过 principal={}/{} via {}",
                principal.subjectId(), principal.credentialId(), principal.credentialType());

        // 2) 防重放/防篡改：与鉴权失败原因明确区分
        RejectionReason replayReason = replayProtector.check(principal, request);
        if (replayReason != null) {
            log.info("判定依据: 防重放拒绝 reason={}, subject={}, requestId={}",
                    replayReason, principal.subjectId(), request.requestId());
            return GatewayDecision.reject(replayReason,
                    "请求未通过防重放/防篡改校验: " + replayReason);
        }

        // 3) 限流：最后执行，拒绝不占额度，原因与前两类区分
        if (!rateLimiter.tryAcquire(principal.subjectId())) {
            log.info("判定依据: 限流拒绝 reason={}, subject={}", RejectionReason.RATE_LIMITED, principal.subjectId());
            return GatewayDecision.reject(RejectionReason.RATE_LIMITED,
                    "主体 " + principal.subjectId() + " 已超出当前窗口配额");
        }

        log.info("判定依据: 放行 subject={}, requestId={}", principal.subjectId(), request.requestId());
        return GatewayDecision.allow(principal);
    }
}
