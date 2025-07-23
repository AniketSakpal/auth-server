package com.security.auth_server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/get/greeting")
    public String getGreetings(){
        return "Hello, You have accessed public endpoint";
    }
}
