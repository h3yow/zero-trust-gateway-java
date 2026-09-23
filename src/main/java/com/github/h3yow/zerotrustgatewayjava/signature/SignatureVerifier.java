package com.github.h3yow.zerotrustgatewayjava.signature;

import com.github.h3yow.zerotrustgatewayjava.auth.RequestContext;
import com.github.h3yow.zerotrustgatewayjava.credential.Credential;

/**
 * 签名/摘要校验：同时负责防篡改（body 摘要）与签名比对。
 */
public interface SignatureVerifier {

    /**
     * 校验 body 摘要与 HMAC 签名。
     *
     * @return true 表示摘要与签名均匹配
     */
    boolean verify(RequestContext request, Credential credential);

    /**
     * 供调用方/测试使用：生成规范串。
     */
    String canonicalString(RequestContext request);

    /**
     * 供调用方/测试使用：对规范串计算签名（十六进制）。
     */
    String sign(RequestContext request, Credential credential);

    /**
     * 供调用方/测试使用：计算请求体 SHA-256（十六进制）。
     */
    String bodyHash(byte[] body);
}
