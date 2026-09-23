package com.github.h3yow.zerotrustgatewayjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 零信任网关装配。
 */
@Configuration
@EnableConfigurationProperties(GatewayProperties.class)
public class GatewayConfig {

    /** 统一时钟，测试时可替换为固定时钟。 */
    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }
}
