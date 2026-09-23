package com.github.h3yow.zerotrustgatewayjava.credential;

/**
 * 凭证类型/版本。不同版本走同一判定流程，仅签名算法不同。
 */
public enum CredentialType {
    /** v1：HmacSHA1，兼容旧调用方。 */
    V1_HMAC_SHA1,
    /** v2：HmacSHA256，当前推荐。 */
    V2_HMAC_SHA256
}
