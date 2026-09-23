package com.github.h3yow.zerotrustgatewayjava.gateway;

/**
 * 凭证校验器：不同类型/版本的凭证各自实现，输出统一主体。
 */
public interface CredentialVerifier {

    /** 是否支持该凭证头（按凭证类型前缀识别）。 */
    boolean supports(String credentialHeader);

    /**
     * 校验凭证（签名需绑定完整请求要素以防篡改）。
     * 成功返回统一主体；失败抛出带可区分原因的 {@link CredentialRejectedException}。
     */
    CallerPrincipal verify(GatewayRequest request);
}
