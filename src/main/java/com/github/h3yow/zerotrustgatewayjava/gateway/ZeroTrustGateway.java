package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 判定编排，固定顺序，每一步的拒绝原因彼此可区分：
 * <pre>鉴权(AuthenticationService) -> 防重放预判(ReplayProtector.precheck)
 *      -> 限流(RateLimiter) -> 防重放提交(ReplayProtector.commit)</pre>
 *
 * <p>并发准入语义（每主体一把准入锁，锁内完成“预判 -> 占配额 -> 提交”）：
 * <ul>
 *   <li>窗口内重复/序号回退/容量满在占用配额之前判定：重复请求即使配额已满也稳定判
 *       REPLAYED_REQUEST，不会被限流原因盖掉，且全程不触碰配额；</li>
 *   <li>配额只被“预判通过且确定会真正执行”的请求占用，占用与提交在同一临界区，
 *       不存在“先占位再归还”的窗口期——并发下配额未真正用满时，全新合法请求不会被
 *       同时涌入的重复请求挤成超限；</li>
 *   <li>被限流拒绝的请求不登记 requestId、不推进序号水位，配额恢复后同一请求重试可正常放行；</li>
 *   <li>同一主体窗口内真正放行的请求数绝不超过配额。</li>
 * </ul>
 * 同一输入在状态一致时结论稳定可复现；输入要素与判定依据都会记录到日志。
 */
@Component
public class ZeroTrustGateway {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustGateway.class);

    private final AuthenticationService authenticationService;
    private final ReplayProtector replayProtector;
    private final RateLimiter rateLimiter;
    /** 每主体准入锁：把“防重放预判 -> 限流占位 -> 防重放提交”合成一个临界区。 */
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

        // 2)+3) 准入临界区：同一主体的“防重放预判 -> 限流占位 -> 防重放提交”整体串行。
        //        预判在占位之前，因此重复/回退/容量满的拒绝与配额完全无涉、原因稳定；
        //        占位与提交原子完成，被拒请求从不临时占着配额挤压其他请求。
        Object admissionLock = admissionLocks.computeIfAbsent(principal.subjectId(), k -> new Object());
        synchronized (admissionLock) {
            // 2) 防重放预判（只读，不登记、不推进水位）：重复请求即使配额已满也在此稳定判重放
            RejectionReason replayVerdict = replayProtector.precheck(principal, request);
            if (replayVerdict != null) {
                log.info("判定依据: 防重放拒绝 reason={}, subject={}, requestId={}（未触碰配额）",
                        replayVerdict, principal.subjectId(), request.requestId());
                return GatewayDecision.reject(replayVerdict,
                        "请求未通过防重放/防篡改校验: " + replayVerdict);
            }

            // 3a) 限流：预判通过的全新请求才参与配额判定。被限流的请求不真正执行，
            //     因此不登记 requestId、不推进水位——配额恢复后同一请求重试可被正常处理。
            if (!rateLimiter.tryAcquire(principal.subjectId())) {
                log.info("判定依据: 限流拒绝 reason={}, subject={}", RejectionReason.RATE_LIMITED, principal.subjectId());
                return GatewayDecision.reject(RejectionReason.RATE_LIMITED,
                        "主体 " + principal.subjectId() + " 已超出当前窗口配额");
            }

            // 3b) 防重放提交：与占位在同一临界区，状态与预判一致，正常路径必然提交成功；
            //     重新判定是兜底，万一失败必须归还刚占的配额（请求未真正执行，不能消耗额度）。
            RejectionReason commitError = replayProtector.commit(principal, request);
            if (commitError != null) {
                rateLimiter.release(principal.subjectId());
                log.warn("判定依据: 防重放提交兜底拒绝并归还配额 subject={}, reason={}",
                        principal.subjectId(), commitError);
                return GatewayDecision.reject(commitError,
                        "请求未通过防重放/防篡改校验: " + commitError);
            }
        }

        log.info("判定依据: 放行 subject={}, requestId={}", principal.subjectId(), request.requestId());
        return GatewayDecision.allow(principal);
    }
}
