package com.github.h3yow.zerotrustgatewayjava.gateway;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 网关装配：启用配置属性并注册过滤器。
 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class GatewayWebConfig {

    @Bean
    public FilterRegistrationBean<GatewayFilter> gatewayFilterRegistration(ZeroTrustGateway gateway,
                                                                           GatewayProperties properties) {
        FilterRegistrationBean<GatewayFilter> registration =
                new FilterRegistrationBean<>(new GatewayFilter(gateway, properties));
        registration.addUrlPatterns("/*");
        registration.setOrder(1);
        return registration;
    }
}
