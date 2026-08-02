package com.innowise.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtKeyConfig {

    @Bean
    public JwtKeyProvider jwtKeyProvider(RsaJwkFactory factory, JwtProperties properties) {
        return new JwtKeyProvider(factory.create(properties));
    }
}
