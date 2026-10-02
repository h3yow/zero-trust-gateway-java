package com.github.h3yow.zerotrustgatewayjava.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 对受保护路径执行零信任校验：
 * 提取凭证与防重放头、缓存正文并由服务端计算 SHA-256（防篡改绑定到签名原文），
 * 再交给 {@link ZeroTrustGateway} 判定。不同拒绝类别映射为不同 HTTP 状态码：
 * 鉴权 401、重放/篡改 409（要素缺失 400）、限流 429。
 */
public class GatewayFilter extends OncePerRequestFilter {

    private static final String H_CREDENTIAL = "Authorization";
    private static final String H_SUBJECT = "X-Subject";
    private static final String H_REQUEST_ID = "X-Request-Id";
    private static final String H_TIMESTAMP = "X-Timestamp";
    private static final String H_SEQUENCE = "X-Sequence";

    private final ZeroTrustGateway gateway;
    private final GatewayProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GatewayFilter(ZeroTrustGateway gateway, GatewayProperties properties) {
        this.gateway = gateway;
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/healthz") || path.equals("/error");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, jakarta.servlet.ServletException {
        CachedBodyRequest cached = new CachedBodyRequest(request);

        GatewayRequest gatewayRequest = new GatewayRequest(
                request.getHeader(H_CREDENTIAL),
                request.getHeader(H_SUBJECT),
                request.getHeader(H_REQUEST_ID),
                parseLongOrNull(request.getHeader(H_TIMESTAMP)),
                parseLongOrNull(request.getHeader(H_SEQUENCE)),
                request.getMethod(),
                request.getRequestURI(),
                sha256Base64(cached.getBody()));

        GatewayDecision decision = gateway.evaluate(gatewayRequest);
        if (!decision.allowed()) {
            writeRejection(response, decision);
            return;
        }
        filterChain.doFilter(cached, response);
    }

    private void writeRejection(HttpServletResponse response, GatewayDecision decision) throws IOException {
        HttpStatus status = mapStatus(decision.reason());
        response.setStatus(status.value());
        if (decision.reason() == RejectionReason.REPLAY_STORE_FULL) {
            // 容量满是暂时状态：旧记录最迟在一个时间偏差窗口后到期，提示调用方按该间隔重试
            response.setHeader("Retry-After", Long.toString(Math.max(1, skewSeconds())));
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("allowed", false);
        payload.put("reason", decision.reason().name());
        payload.put("message", decision.message());
        objectMapper.writeValue(response.getOutputStream(), payload);
    }

    private long skewSeconds() {
        return java.util.concurrent.TimeUnit.MILLISECONDS.toSeconds(
                properties.getTimestampSkewMillis());
    }

    private static HttpStatus mapStatus(RejectionReason reason) {
        return switch (reason) {
            case MISSING_REQUEST_ID, MISSING_TIMESTAMP -> HttpStatus.BAD_REQUEST;
            case RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
            case REPLAY_STORE_FULL -> HttpStatus.SERVICE_UNAVAILABLE;
            case REPLAYED_REQUEST, SEQUENCE_REGRESSION, TIMESTAMP_OUT_OF_WINDOW -> HttpStatus.CONFLICT;
            default -> HttpStatus.UNAUTHORIZED;
        };
    }

    private static Long parseLongOrNull(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String sha256Base64(byte[] body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(body));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /** 缓存请求正文，使过滤器与下游 Controller 都能读取。 */
    private static final class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequest(HttpServletRequest request) throws IOException {
            super(request);
            try (ServletInputStream in = request.getInputStream()) {
                this.body = in.readAllBytes();
            }
        }

        byte[] getBody() {
            return body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return bais.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    // 本地同步读取，无需异步通知
                }

                @Override
                public int read() {
                    return bais.read();
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8));
        }
    }
}
