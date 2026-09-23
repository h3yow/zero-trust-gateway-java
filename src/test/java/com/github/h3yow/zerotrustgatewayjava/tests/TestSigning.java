package com.github.h3yow.zerotrustgatewayjava.tests;

import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;
import com.github.h3yow.zerotrustgatewayjava.signature.HmacSignatureVerifier;

/**
 * 测试辅助：用与生产一致的规范串/HMAC 规则构造请求头。
 */
public final class TestSigning {

    private static final HmacSignatureVerifier VERIFIER = new HmacSignatureVerifier();

    private TestSigning() {
    }

    public static String bodyHash(byte[] body) {
        return VERIFIER.bodyHash(body);
    }

    public static String sign(RequestContext request, Credential credential) {
        return VERIFIER.sign(request, credential);
    }

    /** 组装带完整合法签名头的请求（签名由给定凭证计算）。 */
    public static RequestContext signedRequest(String method, String path, byte[] body,
                                               String keyId, String claimedPrincipal,
                                               long timestamp, String nonce, long sequence,
                                               Credential credential) {
        String bodyHash = bodyHash(body);
        RequestContext unsigned = new RequestContext(
                method, path, body, keyId, claimedPrincipal, timestamp, nonce, sequence, bodyHash, null);
        String signature = sign(unsigned, credential);
        return new RequestContext(
                method, path, body, keyId, claimedPrincipal, timestamp, nonce, sequence, bodyHash, signature);
    }

    /** 替换上下文中的单个字段（record 不可变，返回新实例）。 */
    public static RequestContext withSignature(RequestContext base, String signature) {
        return new RequestContext(base.method(), base.path(), base.body(), base.keyId(), base.claimedPrincipal(),
                base.timestamp(), base.nonce(), base.sequence(), base.bodyHash(), signature);
    }

    public static RequestContext withBodyHash(RequestContext base, String bodyHash) {
        return new RequestContext(base.method(), base.path(), base.body(), base.keyId(), base.claimedPrincipal(),
                base.timestamp(), base.nonce(), base.sequence(), bodyHash, base.signature());
    }

    public static RequestContext withSequence(RequestContext base, long sequence) {
        return new RequestContext(base.method(), base.path(), base.body(), base.keyId(), base.claimedPrincipal(),
                base.timestamp(), base.nonce(), sequence, base.bodyHash(), base.signature());
    }
}
