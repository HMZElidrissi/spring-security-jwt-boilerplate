package me.hmzelidrissi.springsecurityjwtboilerplate.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {
    @GetMapping("/hello")
    public String sayHello() {
        return "Hello from secured endpoint";
    }
}
