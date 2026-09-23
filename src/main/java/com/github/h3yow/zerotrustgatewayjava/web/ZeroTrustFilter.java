package com.github.h3yow.zerotrustgatewayjava.web;

import com.github.h3yow.zerotrustgatewayjava.auth.RejectReason;
import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.engine.Decision;
import com.github.h3yow.zerotrustgatewayjava.engine.DecisionEngine;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * 对 /api/** 执行零信任判定。
 *
 * <p>拒绝时直接写出与 {@link RejectReason} 一一对应的 HTTP 状态与 JSON 体：
 * <ul>
 *   <li>鉴权类（缺失/未知/过期/签名/主体/篡改/格式）→ 401</li>
 *   <li>时间窗口/重放/序号回退 → 409</li>
 *   <li>限流 → 429</li>
 * </ul>
 */
public class ZeroTrustFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustFilter.class);

    private static final Set<RejectReason> CONFLICT_REASONS = Set.of(
            RejectReason.STALE_TIMESTAMP,
            RejectReason.NONCE_REPLAY,
            RejectReason.SEQUENCE_ROLLBACK);

    private final DecisionEngine decisionEngine;

    public ZeroTrustFilter(DecisionEngine decisionEngine) {
        this.decisionEngine = decisionEngine;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        byte[] body = request.getInputStream().readAllBytes();
        CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request, body);

        RequestContext context = new RequestContext(
                request.getMethod(),
                request.getRequestURI(),
                body,
                request.getHeader("X-ZT-Key-Id"),
                request.getHeader("X-ZT-Principal"),
                parseLongHeader(request, "X-ZT-Timestamp"),
                request.getHeader("X-ZT-Nonce"),
                parseLongHeader(request, "X-ZT-Sequence"),
                request.getHeader("X-ZT-Body-Sha256"),
                request.getHeader("X-ZT-Signature"));

        Decision decision = decisionEngine.evaluate(context);
        if (!decision.allowed()) {
            writeDenial(response, decision);
            return;
        }

        cached.setAttribute("ztg.principal", decision.principal());
        response.setHeader("X-ZT-Principal", decision.principal());
        response.setIntHeader("X-RateLimit-Remaining",
                decision.rateLimitRemaining() == null ? -1 : decision.rateLimitRemaining().intValue());
        filterChain.doFilter(cached, response);
    }

    private void writeDenial(HttpServletResponse response, Decision decision) throws IOException {
        HttpStatus status = decision.reason() == RejectReason.RATE_LIMITED
                ? HttpStatus.TOO_MANY_REQUESTS
                : CONFLICT_REASONS.contains(decision.reason())
                        ? HttpStatus.CONFLICT
                        : HttpStatus.UNAUTHORIZED;

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        String json = """
                {"allowed":false,"reason":"%s","detail":"%s","keyId":%s,"principal":%s}
                """.formatted(
                decision.reason().name(),
                jsonEscape(decision.detail()),
                decision.keyId() == null ? "null" : "\"" + jsonEscape(decision.keyId()) + "\"",
                decision.principal() == null ? "null" : "\"" + jsonEscape(decision.principal()) + "\"");
        log.info("denial response: httpStatus={} reason={}", status.value(), decision.reason());
        response.getWriter().write(json);
    }

    private static Long parseLongHeader(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
