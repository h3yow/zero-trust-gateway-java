package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 不经过零信任过滤器的本地健康检查端点。
 */
@RestController
public class HealthController {

    @GetMapping("/healthz")
    public Map<String, Object> healthz() {
        return Map.of("status", "ok");
    }
}
