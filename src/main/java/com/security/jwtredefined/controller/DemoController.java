package com.security.jwtredefined.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class DemoController {

    @GetMapping("private")
    public ResponseEntity<String> getPrivateData() {
        return ResponseEntity.ok("Hello from secured endpoint");
    }
    
    @GetMapping("public")
    public ResponseEntity<String> getPublicData() {
        return ResponseEntity.ok("This is public endpoint");
    }

}
