package com.innowise.authservice.config;

import com.innowise.authservice.config.jwk.JwkComposer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtKeyConfig {

    @Bean
    public JwtKeyProvider jwtKeyProvider(JwkComposer jwkComposer) {
        return new JwtKeyProvider(jwkComposer.compose());
    }
}
