package com.github.h3yow.zerotrustgatewayjava.tests.web;

import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.credential.CredentialStore;
import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.tests.TestSigning;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Clock;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 Web 测试：真实 Spring 上下文 + MockMvc，
 * 使用 application.properties 中登记的本地凭证，覆盖正常/越权/重放/限流边界。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class ZeroTrustWebIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustWebIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CredentialStore credentialStore;

    @Autowired
    private Clock clock;

    private long seq = 1;

    private Credential v1;
    private Credential v2;

    @BeforeEach
    void setUp() {
        v1 = credentialStore.find("demo-key-v1").orElseThrow();
        v2 = credentialStore.find("demo-key-v2").orElseThrow();
        seq = 1;
    }

    /** 发起一个带合法头的 POST，返回 MvcResult 以便断言；nonce 唯一、序号自增。 */
    private MvcResult signedPost(Credential credential, String nonce, long sequence, String body) throws Exception {
        RequestContext ctx = TestSigning.signedRequest("POST", "/api/echo", body.getBytes(),
                credential.keyId(), credential.principal(),
                clock.instant().getEpochSecond(), nonce, sequence, credential);
        return mockMvc.perform(post("/api/echo")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(body)
                        .header("X-ZT-Key-Id", ctx.keyId())
                        .header("X-ZT-Principal", ctx.claimedPrincipal())
                        .header("X-ZT-Timestamp", ctx.timestamp())
                        .header("X-ZT-Nonce", ctx.nonce())
                        .header("X-ZT-Sequence", ctx.sequence())
                        .header("X-ZT-Body-Sha256", ctx.bodyHash())
                        .header("X-ZT-Signature", ctx.signature()))
                .andReturn();
    }

    private long nextSeq() {
        return seq++;
    }

    @Test
    @DisplayName("V1 凭证正常请求 -> 200，响应回显并带归一主体/剩余配额头")
    void validV1RequestPasses() throws Exception {
        MvcResult result = signedPost(v1, "web-nonce-1", nextSeq(), "hello");
        log.info("valid v1 -> status={}, body={}", result.getResponse().getStatus(),
                result.getResponse().getContentAsString());

        // 直接对已返回的 MvcResult 做断言
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(200);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString()).isEqualTo("hello");
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getHeader("X-ZT-Principal"))
                .isEqualTo("svc-demo");
    }

    @Test
    @DisplayName("无凭证请求 -> 401 MISSING_CREDENTIAL")
    void missingCredential401() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/echo").content("x")).andReturn();
        log.info("missing credential -> status={}, body={}", result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(401);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .contains("MISSING_CREDENTIAL");
    }

    @Test
    @DisplayName("未知 keyId -> 401 UNKNOWN_KEY_ID")
    void unknownKeyId401() throws Exception {
        RequestContext ctx = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                "ghost-key", "svc-demo", clock.instant().getEpochSecond(),
                "web-unknown", nextSeq(), v1);
        MvcResult result = mockMvc.perform(post("/api/echo").content("x")
                .header("X-ZT-Key-Id", "ghost-key")
                .header("X-ZT-Principal", "svc-demo")
                .header("X-ZT-Timestamp", ctx.timestamp())
                .header("X-ZT-Nonce", ctx.nonce())
                .header("X-ZT-Sequence", ctx.sequence())
                .header("X-ZT-Body-Sha256", ctx.bodyHash())
                .header("X-ZT-Signature", ctx.signature())).andReturn();

        log.info("unknown keyId -> status={}, body={}", result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(401);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .contains("UNKNOWN_KEY_ID");
    }

    @Test
    @DisplayName("篡改请求体 -> 401 BODY_TAMPERED（签名头对应旧 body）")
    void tamperedBody401() throws Exception {
        RequestContext ctx = TestSigning.signedRequest("POST", "/api/echo", "original".getBytes(),
                v1.keyId(), v1.principal(), clock.instant().getEpochSecond(),
                "web-tamper", nextSeq(), v1);
        MvcResult result = mockMvc.perform(post("/api/echo").content("tampered")
                .header("X-ZT-Key-Id", ctx.keyId())
                .header("X-ZT-Principal", ctx.claimedPrincipal())
                .header("X-ZT-Timestamp", ctx.timestamp())
                .header("X-ZT-Nonce", ctx.nonce())
                .header("X-ZT-Sequence", ctx.sequence())
                .header("X-ZT-Body-Sha256", ctx.bodyHash())
                .header("X-ZT-Signature", ctx.signature())).andReturn();

        log.info("tampered body -> status={}, body={}", result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(401);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .contains("BODY_TAMPERED");
    }

    @Test
    @DisplayName("越权：自述主体与凭证不符 -> 401 PRINCIPAL_MISMATCH")
    void principalMismatch401() throws Exception {
        RequestContext ctx = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                v1.keyId(), "svc-attacker", clock.instant().getEpochSecond(),
                "web-mismatch", nextSeq(), v1);
        MvcResult response = mockMvc.perform(post("/api/echo").content("x")
                .header("X-ZT-Key-Id", ctx.keyId())
                .header("X-ZT-Principal", "svc-attacker")
                .header("X-ZT-Timestamp", ctx.timestamp())
                .header("X-ZT-Nonce", ctx.nonce())
                .header("X-ZT-Sequence", ctx.sequence())
                .header("X-ZT-Body-Sha256", ctx.bodyHash())
                .header("X-ZT-Signature", ctx.signature())).andReturn();

        log.info("principal mismatch -> status={}, body={}", response.getResponse().getStatus(),
                response.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(response.getResponse().getStatus()).isEqualTo(401);
        org.assertj.core.api.Assertions.assertThat(response.getResponse().getContentAsString())
                .contains("PRINCIPAL_MISMATCH");
    }

    @Test
    @DisplayName("重放：相同签名请求发两次 -> 第一次 200，第二次 409 NONCE_REPLAY")
    void replay409() throws Exception {
        String nonce = "web-replay";
        long sequence = nextSeq();
        MvcResult first = signedPost(v2, nonce, sequence, "replay-me");
        MvcResult second = signedPost(v2, nonce, sequence, "replay-me");

        log.info("replay: first={}, second={} body={}", first.getResponse().getStatus(),
                second.getResponse().getStatus(), second.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(first.getResponse().getStatus()).isEqualTo(200);
        org.assertj.core.api.Assertions.assertThat(second.getResponse().getStatus()).isEqualTo(409);
        org.assertj.core.api.Assertions.assertThat(second.getResponse().getContentAsString())
                .contains("NONCE_REPLAY");
    }

    @Test
    @DisplayName("过期时间戳 -> 409 STALE_TIMESTAMP，与重放原因可区分")
    void staleTimestamp409() throws Exception {
        long oldTs = clock.instant().getEpochSecond() - 120;
        RequestContext ctx = TestSigning.signedRequest("POST", "/api/echo", "x".getBytes(),
                v1.keyId(), v1.principal(), oldTs, "web-stale", nextSeq(), v1);
        MvcResult result = mockMvc.perform(post("/api/echo").content("x")
                .header("X-ZT-Key-Id", ctx.keyId())
                .header("X-ZT-Principal", ctx.claimedPrincipal())
                .header("X-ZT-Timestamp", ctx.timestamp())
                .header("X-ZT-Nonce", ctx.nonce())
                .header("X-ZT-Sequence", ctx.sequence())
                .header("X-ZT-Body-Sha256", ctx.bodyHash())
                .header("X-ZT-Signature", ctx.signature())).andReturn();

        log.info("stale timestamp -> status={}, body={}", result.getResponse().getStatus(),
                result.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(409);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .contains("STALE_TIMESTAMP");
    }

    @Test
    @DisplayName("限流边界：同主体连续请求，前 10 个 200，第 11 个 429 RATE_LIMITED")
    void rateLimitBoundary429() throws Exception {
        // 该测试依赖全新 10 秒窗口：直接顺序打满配额
        for (int i = 1; i <= 10; i++) {
            MvcResult result = signedPost(v1, "web-rl-" + i, nextSeq(), "x");
            org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus())
                    .as("request %d should pass", i)
                    .isEqualTo(200);
        }
        MvcResult overflow = signedPost(v1, "web-rl-overflow", nextSeq(), "x");
        log.info("rate limit overflow -> status={}, body={}", overflow.getResponse().getStatus(),
                overflow.getResponse().getContentAsString());
        org.assertj.core.api.Assertions.assertThat(overflow.getResponse().getStatus()).isEqualTo(429);
        org.assertj.core.api.Assertions.assertThat(overflow.getResponse().getContentAsString())
                .contains("RATE_LIMITED");
    }
}
