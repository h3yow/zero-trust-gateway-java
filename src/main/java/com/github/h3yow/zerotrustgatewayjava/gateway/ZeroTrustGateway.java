package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 判定编排，固定顺序，每一步的拒绝原因彼此可区分：
 * <pre>鉴权(AuthenticationService) -> 防重放只读预检(ReplayProtector.inspect)
 *      -> 限流(RateLimiter) -> 防重放原子复检+登记(ReplayProtector.check)</pre>
 *
 * <p>并发语义：预检 -> 占配额 -> 登记提交 这三步在<b>每主体一把锁</b>内原子完成，
 * 同一主体的并发请求被串行化判定，因此：
 * <ul>
 *   <li>窗口内重复请求在预检阶段即稳定判 {@code REPLAYED_REQUEST}，永远不触碰配额——
 *       即使配额已满也不会被超限原因盖掉，也不会临时占着配额挤掉本该放行的新请求；</li>
 *   <li>配额之内且无窗口内重复的全新请求必然放行，不会被同时涌入的重复请求牵连成超限；</li>
 *   <li>被限流拒绝的请求不登记 requestId、不推进序号水位，配额恢复后同一请求重试可正常处理；</li>
 *   <li>通过预检与限流、但在登记复检时被拒（如容量恰好打满）的请求会归还刚占用的配额。</li>
 * </ul>
 * 同一输入在状态一致时结论稳定可复现；输入要素与判定依据都会记录到日志。
 */
@Component
public class ZeroTrustGateway {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustGateway.class);

    private final AuthenticationService authenticationService;
    private final ReplayProtector replayProtector;
    private final RateLimiter rateLimiter;
    /** 每主体一把判定锁：预检 -> 占配额 -> 登记提交 在同一临界区原子完成。 */
    private final ConcurrentHashMap<String, Object> admissionLocks = new ConcurrentHashMap<>();

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

        // 2) 准入判定（每主体锁内原子：只读预检 -> 占配额 -> 登记提交）
        Object admissionLock = admissionLocks.computeIfAbsent(principal.subjectId(), k -> new Object());
        synchronized (admissionLock) {
            // 2a) 防重放只读预检：窗口内重复 / 序号回退 / 容量满在此直接定案，不触碰配额。
            //     因此重复请求即使配额已满也稳定判重放，也不会临时占住配额挤掉新请求。
            RejectionReason precheck = replayProtector.inspect(principal, request);
            if (precheck != null) {
                log.info("判定依据: 防重放预检拒绝(不占配额) reason={}, subject={}, requestId={}",
                        precheck, principal.subjectId(), request.requestId());
                return GatewayDecision.reject(precheck,
                        "请求未通过防重放/防篡改校验: " + precheck);
            }

            // 2b) 限流：只有“预检通过、确属全新”的请求才参与配额竞争。被限流的请求不真正执行，
            //     因此既不登记 requestId、也不推进序号水位——配额恢复后同一请求重试可被正常处理。
            if (!rateLimiter.tryAcquire(principal.subjectId())) {
                log.info("判定依据: 限流拒绝 reason={}, subject={}", RejectionReason.RATE_LIMITED, principal.subjectId());
                return GatewayDecision.reject(RejectionReason.RATE_LIMITED,
                        "主体 " + principal.subjectId() + " 已超出当前窗口配额");
            }

            // 2c) 防重放原子复检+登记：与预检同口径，在同一主体锁内结果必然一致；
            //     仍保留复检以防御锁外直接改写状态的调用方。复检失败必须归还刚占用的配额。
            RejectionReason replayReason = replayProtector.check(principal, request);
            if (replayReason != null) {
                rateLimiter.release(principal.subjectId());
                log.info("判定依据: 防重放登记拒绝并归还配额 reason={}, subject={}, requestId={}",
                        replayReason, principal.subjectId(), request.requestId());
                return GatewayDecision.reject(replayReason,
                        "请求未通过防重放/防篡改校验: " + replayReason);
            }
        }

        log.info("判定依据: 放行 subject={}, requestId={}", principal.subjectId(), request.requestId());
        return GatewayDecision.allow(principal);
    }
}
