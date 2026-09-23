package com.github.h3yow.zerotrustgatewayjava.auth;

/**
 * 从入站 HTTP 请求归一化得到的待校验请求视图。
 *
 * @param method        HTTP 方法（大写）
 * @param path          请求路径（不含 query）
 * @param body          请求体原始字节
 * @param keyId         X-ZT-Key-Id
 * @param claimedPrincipal X-ZT-Principal（调用方自述主体，可为空）
 * @param timestamp     X-ZT-Timestamp（Unix 秒）
 * @param nonce         X-ZT-Nonce
 * @param sequence      X-ZT-Sequence（单调序号）
 * @param bodyHash      X-ZT-Body-Sha256（请求体 SHA-256 的十六进制）
 * @param signature     X-ZT-Signature（十六进制 HMAC）
 */
public record RequestContext(
        String method,
        String path,
        byte[] body,
        String keyId,
        String claimedPrincipal,
        Long timestamp,
        String nonce,
        Long sequence,
        String bodyHash,
        String signature) {
}
