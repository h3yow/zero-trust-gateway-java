package com.github.h3yow.zerotrustgatewayjava.gateway;

import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护的演示接口。
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    @PostMapping("/echo")
    public Map<String, Object> echo(@RequestBody(required = false) Map<String, Object> body) {
        return Map.of("ok", true, "echo", body == null ? Map.of() : body);
    }
}
