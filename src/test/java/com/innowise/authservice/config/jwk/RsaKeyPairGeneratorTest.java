package com.innowise.authservice.config.jwk;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class RsaKeyPairGeneratorTest {

    private final RsaKeyPairGenerator generator = new RsaKeyPairGenerator();

    @Test
    void generate_returns_private_key_of_configured_size() throws Exception {
        RSAKey result = generator.generate();
        assertThat(result.isPrivate()).isTrue();
        assertThat(result.toRSAPrivateKey().getModulus().bitLength()).isEqualTo(2048);
    }

    @Test
    void generate_called_twice_returns_distinct_keys() {
        RSAKey first = generator.generate();
        RSAKey second = generator.generate();
        assertThat(first.getModulus()).isNotEqualTo(second.getModulus());
    }

}