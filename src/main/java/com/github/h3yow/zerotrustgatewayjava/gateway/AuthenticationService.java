package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 鉴权入口：不同类型/版本的凭证都走同一套判定流程——
 * 缺失 -> 类型识别 -> 结构解析 -> 主体一致性 -> 有效期 -> 签名，任一步失败即给出可区分原因。
 */
@Service
public class AuthenticationService {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationService.class);

    private final List<CredentialVerifier> verifiers;

    public AuthenticationService(List<CredentialVerifier> verifiers) {
        this.verifiers = List.copyOf(verifiers);
    }

    public CallerPrincipal authenticate(GatewayRequest request) {
        String header = request.credentialHeader();
        if (header == null || header.isBlank()) {
            throw new CredentialRejectedException(RejectionReason.MISSING_CREDENTIAL, "请求未携带凭证头");
        }

        for (CredentialVerifier verifier : verifiers) {
            if (verifier.supports(header)) {
                return verifier.verify(request);
            }
        }

        log.warn("凭证拒绝: reason={}, headerPrefix={}", RejectionReason.UNKNOWN_CREDENTIAL_TYPE,
                header.length() > 16 ? header.substring(0, 16) : header);
        throw new CredentialRejectedException(RejectionReason.UNKNOWN_CREDENTIAL_TYPE,
                "无法识别的凭证类型: " + header);
    }
}
