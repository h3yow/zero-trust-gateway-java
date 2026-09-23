package com.github.h3yow.zerotrustgatewayjava.engine;

import com.github.h3yow.zerotrustgatewayjava.auth.RejectReason;
import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.config.GatewayProperties;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.credential.CredentialStore;
import com.github.h3yow.zerotrustgatewayjava.ratelimit.RateLimitResult;
import com.github.h3yow.zerotrustgatewayjava.ratelimit.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.replay.ReplayGuard;
import com.github.h3yow.zerotrustgatewayjava.replay.ReplayResult;
import com.github.h3yow.zerotrustgatewayjava.signature.SignatureVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * 零信任判定主流程的默认实现。
 *
 * <p>固定判定顺序，每个失败点对应唯一 {@link RejectReason}，结论可解释、同输入稳定：
 * <ol>
 *   <li>凭证存在性与格式（缺失/未知/格式错误）</li>
 *   <li>凭证有效期（过期）</li>
 *   <li>主体一致性（自述主体与凭证归一主体不符）</li>
 *   <li>body 摘要 + HMAC 签名（篡改/签名不符）</li>
 *   <li>时间窗口（过期请求）</li>
 *   <li>按主体限流（配额）</li>
 *   <li>nonce 唯一性与序号单调（重放/回退）；失败时归还限流额度</li>
 * </ol>
 */
@Component
public class DefaultDecisionEngine implements DecisionEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultDecisionEngine.class);

    private final CredentialStore credentialStore;
    private final SignatureVerifier signatureVerifier;
    private final RateLimiter rateLimiter;
    private final ReplayGuard replayGuard;
    private final GatewayProperties properties;
    private final Clock clock;

    public DefaultDecisionEngine(CredentialStore credentialStore,
                                 SignatureVerifier signatureVerifier,
                                 RateLimiter rateLimiter,
                                 ReplayGuard replayGuard,
                                 GatewayProperties properties,
                                 Clock clock) {
        this.credentialStore = credentialStore;
        this.signatureVerifier = signatureVerifier;
        this.rateLimiter = rateLimiter;
        this.replayGuard = replayGuard;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public Decision evaluate(RequestContext request) {
        log.info("evaluate request: method={}, path={}, keyId={}, claimedPrincipal={}, ts={}, nonce={}, seq={}, bodyBytes={}",
                request.method(), request.path(), request.keyId(), request.claimedPrincipal(),
                request.timestamp(), request.nonce(), request.sequence(),
                request.body() == null ? 0 : request.body().length);

        // 1. 凭证缺失
        if (isBlank(request.keyId())) {
            return reject(null, null, request, RejectReason.MISSING_CREDENTIAL,
                    "missing X-ZT-Key-Id header");
        }

        // 2. 数值类头部格式
        if (request.timestamp() == null) {
            return reject(null, request.keyId(), request, RejectReason.MALFORMED_REQUEST,
                    "X-ZT-Timestamp missing or not a unix-second integer");
        }
        if (isBlank(request.nonce()) || isBlank(request.bodyHash()) || isBlank(request.signature())) {
            return reject(null, request.keyId(), request, RejectReason.MALFORMED_REQUEST,
                    "one of X-ZT-Nonce / X-ZT-Body-Sha256 / X-ZT-Signature is missing");
        }
        if (request.sequence() == null) {
            return reject(null, request.keyId(), request, RejectReason.MALFORMED_REQUEST,
                    "X-ZT-Sequence missing or not an integer");
        }

        // 3. 凭证登记
        Optional<Credential> credentialOpt = credentialStore.find(request.keyId());
        if (credentialOpt.isEmpty()) {
            return reject(null, request.keyId(), request, RejectReason.UNKNOWN_KEY_ID,
                    "keyId is not registered locally: " + request.keyId());
        }
        Credential credential = credentialOpt.get();

        // 4. 凭证过期
        if (credential.expiresAt() != null && !clock.instant().isBefore(credential.expiresAt())) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.CREDENTIAL_EXPIRED,
                    "credential expired at " + credential.expiresAt() + ", now " + clock.instant());
        }

        // 5. 主体一致性：多种凭证归一到同一 principal，禁止凭证与自述主体不一致
        if (!isBlank(request.claimedPrincipal()) && !credential.principal().equals(request.claimedPrincipal())) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.PRINCIPAL_MISMATCH,
                    "claimed principal '" + request.claimedPrincipal() + "' does not match credential principal '"
                            + credential.principal() + "'");
        }

        // 6. 防篡改 + 签名（两类原因可区分：先比 body 摘要，再比签名）
        String expectedBodyHash = signatureVerifier.bodyHash(request.body() == null ? new byte[0] : request.body());
        if (!constantTimeHexEquals(expectedBodyHash, request.bodyHash())) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.BODY_TAMPERED,
                    "body sha256 mismatch: expected=" + expectedBodyHash + " got=" + request.bodyHash());
        }
        String expectedSignature = signatureVerifier.sign(request, credential);
        if (!constantTimeHexEquals(expectedSignature, request.signature())) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.SIGNATURE_MISMATCH,
                    "hmac signature does not match canonical string; credential type=" + credential.type());
        }

        // 7. 时间窗口：拒绝过旧/过新请求，抑制重放
        long nowSeconds = clock.instant().getEpochSecond();
        long skew = Math.abs(nowSeconds - request.timestamp());
        if (skew > properties.timestampWindowSeconds()) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.STALE_TIMESTAMP,
                    "timestamp skew " + skew + "s exceeds window " + properties.timestampWindowSeconds() + "s");
        }

        // 8. 按主体限流
        RateLimitResult rl = rateLimiter.tryAcquire(credential.principal());
        if (!rl.allowed()) {
            return reject(credential.principal(), credential.keyId(), request, RejectReason.RATE_LIMITED,
                    "quota exhausted: limit=" + rl.limit() + " per window, reset in " + rl.windowResetMs() + "ms");
        }

        // 9. 重放/序号（原子提交）。失败则归还此前占用的配额，避免额度被永久占用。
        ReplayResult replay = replayGuard.commit(
                credential.principal(), request.nonce(), request.sequence(), clock.millis());
        return switch (replay) {
            case ACCEPTED -> {
                Decision decision = Decision.allow(credential.principal(), credential.keyId(),
                        rl.remaining(), rl.limit());
                log.info("decision=ALLOW principal={} keyId={} nonce={} seq={} remaining={}/{}",
                        credential.principal(), credential.keyId(), request.nonce(), request.sequence(),
                        rl.remaining(), rl.limit());
                yield decision;
            }
            case DUPLICATE_NONCE -> {
                rateLimiter.release(credential.principal());
                yield reject(credential.principal(), credential.keyId(), request, RejectReason.NONCE_REPLAY,
                        "nonce already seen within TTL: " + request.nonce());
            }
            case SEQUENCE_ROLLBACK -> {
                rateLimiter.release(credential.principal());
                yield reject(credential.principal(), credential.keyId(), request, RejectReason.SEQUENCE_ROLLBACK,
                        "sequence not strictly increasing: " + request.sequence());
            }
        };
    }

    private Decision reject(String principal, String keyId, RequestContext request,
                            RejectReason reason, String detail) {
        log.warn("decision=DENY principal={} keyId={} nonce={} seq={} reason={} detail={}",
                principal, keyId, request.nonce(), request.sequence(), reason, detail);
        return Decision.reject(principal, keyId, reason, detail);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static boolean constantTimeHexEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= Character.toLowerCase(a.charAt(i)) ^ Character.toLowerCase(b.charAt(i));
        }
        return diff == 0;
    }
}
