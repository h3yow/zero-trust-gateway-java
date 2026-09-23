package com.github.h3yow.zerotrustgatewayjava.web;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护的演示资源。
 */
@RestController
@RequestMapping("/api")
public class EchoController {

    @PostMapping("/echo")
    public String echo(@RequestBody(required = false) String body) {
        return body;
    }
}
