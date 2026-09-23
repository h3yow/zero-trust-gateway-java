package com.github.h3yow.zerotrustgatewayjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.zerotrustgatewayjava.gateway.GatewayRequest;
import com.github.h3yow.zerotrustgatewayjava.gateway.HmacCredentialVerifier;
import com.github.h3yow.zerotrustgatewayjava.gateway.LocalCredentialRegistry;
import com.github.h3yow.zerotrustgatewayjava.gateway.RateLimiter;
import com.github.h3yow.zerotrustgatewayjava.gateway.ReplayProtector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * 端到端 HTTP 测试：真实过滤器链 + 状态码 + JSON 原因码。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayHttpIntegrationTests {

    private static final Logger log = LoggerFactory.getLogger(GatewayHttpIntegrationTests.class);

    @LocalServerPort
    private int port;
    @Autowired
    private LocalCredentialRegistry registry;
    @Autowired
    private RateLimiter rateLimiter;
    @Autowired
    private ReplayProtector replayProtector;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper json = new ObjectMapper();
    private long seq = 0;

    @BeforeEach
    void resetState() {
        rateLimiter.reset();
        replayProtector.reset();
    }

    private HttpResponse<String> send(GatewayRequest gw, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + gw.path()))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("Authorization", gw.credentialHeader())
                .header("X-Request-Id", gw.requestId())
                .header("X-Timestamp", Long.toString(gw.timestamp()))
                .header("X-Sequence", Long.toString(gw.sequence()))
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void assertReason(HttpResponse<String> resp, int expectedStatus, String expectedReason) throws Exception {
        JsonNode node = json.readTree(resp.body());
        log.info("HTTP 断言: 期望 status={}/{}, 实际 status={}, body={}",
                expectedStatus, expectedReason, resp.statusCode(), resp.body());
        assertEquals(expectedStatus, resp.statusCode());
        assertEquals(expectedReason, node.path("reason").asText());
    }

    @Test
    @DisplayName("HTTP 正常：合法 HMAC1 请求 200 并得到业务回显")
    void validHttpRequestPasses() throws Exception {
        String body = "{\"msg\":\"hello\"}";
        long ts = System.currentTimeMillis();
        GatewayRequest gw = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                UUID.randomUUID().toString(), ts, ++seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256(body));
        HttpResponse<String> resp = send(gw, body);
        assertEquals(200, resp.statusCode(), resp.body());
        assertTrue(resp.body().contains("hello"));
    }

    @Test
    @DisplayName("HTTP 越权：无凭证 -> 401 MISSING_CREDENTIAL")
    void missingCredentialReturns401() throws Exception {
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/echo"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertReason(resp, 401, "MISSING_CREDENTIAL");
    }

    @Test
    @DisplayName("HTTP 越权：篡改正文 -> 401 SIGNATURE_MISMATCH")
    void tamperedBodyReturns401() throws Exception {
        String signedBody = "{\"a\":1}";
        long ts = System.currentTimeMillis();
        GatewayRequest gw = SignedRequestFactory.signed(registry, "HMAC2", "alice", "alice",
                UUID.randomUUID().toString(), ts, ++seq, "POST", "/api/echo",
                SignedRequestFactory.bodySha256(signedBody));
        HttpResponse<String> resp = send(gw, "{\"a\":2}");
        assertReason(resp, 401, "SIGNATURE_MISMATCH");
    }

    @Test
    @DisplayName("HTTP 重放：同一请求提交两次 -> 200 后 409 REPLAYED_REQUEST")
    void replayReturns409() throws Exception {
        String body = "{\"x\":1}";
        long ts = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        GatewayRequest gw = SignedRequestFactory.signed(registry, "HMAC1", "bob", "bob",
                requestId, ts, 100L, "POST", "/api/echo", SignedRequestFactory.bodySha256(body));
        assertEquals(200, send(gw, body).statusCode());
        assertReason(send(gw, body), 409, "REPLAYED_REQUEST");
    }

    @Test
    @DisplayName("HTTP 限流：配额 5 用尽 -> 429 RATE_LIMITED，与 401/409 可区分")
    void rateLimitReturns429() throws Exception {
        String body = "{}";
        String bodySha = SignedRequestFactory.bodySha256(body);
        long ts = System.currentTimeMillis();
        for (int i = 1; i <= 5; i++) {
            GatewayRequest gw = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                    UUID.randomUUID().toString(), ts + i, (long) i, "POST", "/api/echo", bodySha);
            assertEquals(200, send(gw, body).statusCode());
        }
        GatewayRequest over = SignedRequestFactory.signed(registry, "HMAC1", "alice", "alice",
                UUID.randomUUID().toString(), ts + 6, 6L, "POST", "/api/echo", bodySha);
        assertReason(send(over, body), 429, "RATE_LIMITED");
    }

    @Test
    @DisplayName("HTTP 健康检查不经网关直接 200")
    void healthzBypassesGateway() throws Exception {
        HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/healthz")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("ok"));
    }
}
