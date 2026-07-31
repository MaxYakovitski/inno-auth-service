package com.innowise.authservice.controller;

import com.innowise.authservice.config.JwtKeyProvider;
import com.innowise.authservice.config.JwtProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.time.Duration;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;


class JwksControllerTest {

    private final JwtKeyProvider keyProvider = new JwtKeyProvider(
            new JwtProperties(null, null, "test-key", Duration.ofMinutes(15), Duration.ofDays(7)));

    private final JwksController controller = new JwksController(keyProvider);

    @Test
    void returns_public_JwkSet() {
        var response = controller.jwks();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).asString().contains("test-key", "RSA");
    }

    @Test
    void is_Cacheable() {
        var response = controller.jwks();
        assertThat(response.getHeaders().getCacheControl()).contains("max-age=600");
    }

}