package com.github.h3yow.zerotrustgatewayjava.web;

import com.github.h3yow.zerotrustgatewayjava.engine.DecisionEngine;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ZeroTrustWebConfig {

    @Bean
    public FilterRegistrationBean<ZeroTrustFilter> zeroTrustFilter(DecisionEngine decisionEngine) {
        FilterRegistrationBean<ZeroTrustFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new ZeroTrustFilter(decisionEngine));
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        return registration;
    }
}
