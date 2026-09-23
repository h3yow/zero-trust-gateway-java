package com.github.h3yow.zerotrustgatewayjava.gateway;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 本地零信任网关配置（全部来自 application.properties，无外部依赖）。
 */
@ConfigurationProperties(prefix = "zero-trust.gateway")
public class GatewayProperties {

    /** 凭证：subjectId -> 密钥（本地内置，base64）。 */
    private String credentials = "";
    /** 每主体每窗口请求配额。 */
    private long quotaPerWindow = 10;
    /** 限流窗口毫秒数。 */
    private long windowMillis = 60_000;
    /** 时间戳允许偏差毫秒数。 */
    private long timestampSkewMillis = 30_000;

    public String getCredentials() { return credentials; }
    public void setCredentials(String credentials) { this.credentials = credentials; }

    public long getQuotaPerWindow() { return quotaPerWindow; }
    public void setQuotaPerWindow(long quotaPerWindow) { this.quotaPerWindow = quotaPerWindow; }

    public long getWindowMillis() { return windowMillis; }
    public void setWindowMillis(long windowMillis) { this.windowMillis = windowMillis; }

    public long getTimestampSkewMillis() { return timestampSkewMillis; }
    public void setTimestampSkewMillis(long timestampSkewMillis) { this.timestampSkewMillis = timestampSkewMillis; }
}
