package com.innowise.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties (
        String privateKey,
        String publicKey,
        String keyId,
        Duration accessTokenExpiration,
        Duration refreshTokenExpiration) {
}
