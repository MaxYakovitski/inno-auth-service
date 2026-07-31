package com.innowise.authservice.controller;

import com.innowise.authservice.config.JwtKeyProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private static final Duration CACHE_TTL = Duration.ofMinutes(10);

    private final JwtKeyProvider keyProvider;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(CACHE_TTL).cachePublic())
                .body(keyProvider.publicJwkSet());
    }
}
