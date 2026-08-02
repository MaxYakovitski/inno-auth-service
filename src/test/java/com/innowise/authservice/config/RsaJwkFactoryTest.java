package com.innowise.authservice.config;

import com.innowise.authservice.controller.TestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class RsaJwkFactoryTest {

    private static final String KEY_ID = "test-key";
    private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TTL = Duration.ofDays(7);

    private final RsaJwkFactory factory = new RsaJwkFactory();

    private static JwtProperties properties(Resource privateKey, Resource publicKey) {
        return new JwtProperties(privateKey, publicKey, KEY_ID, ACCESS_TTL, REFRESH_TTL);
    }

    private static Resource pem(String label, byte[] der) {
        String content = "-----BEGIN %s-----%n%s%n-----END %s-----%n"
                .formatted(label, Base64.getMimeEncoder().encodeToString(der), label);
        return new ByteArrayResource(content.getBytes(StandardCharsets.UTF_8));
    }

    private static Resource incorrectKey() {
        return new ByteArrayResource("not-a-key".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void create_configured_keys_reads_them_from_pem() throws Exception {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);

        RSAKey result = factory.create(properties(
                pem("PRIVATE KEY", source.toRSAPrivateKey().getEncoded()),
                pem("PUBLIC KEY", source.toRSAPublicKey().getEncoded())));

        assertThat(result.getModulus()).isEqualTo(source.getModulus());
        assertThat(result.isPrivate()).isTrue();
        assertThat(result.getKeyID()).isEqualTo(KEY_ID);
    }

    @Test
    void create_no_keys_configured_generates_new_pair() {
        assertThat(factory.create(properties(null, null)).isPrivate()).isTrue();
    }

    @Test
    void create_no_keys_configured_generates_distinct_pair() {
        assertThat(factory.create(properties(null, null)).getModulus())
                .isNotEqualTo(factory.create(properties(null, null)).getModulus());
    }

    @Test
    void create_incorrect_private_key_throws_illegal_state() throws Exception {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        JwtProperties properties = properties(
                incorrectKey(),
                pem("PUBLIC KEY", source.toRSAPublicKey().getEncoded()));

        assertThatThrownBy(() -> factory.create(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("jwt.private-key");
    }

    @Test
    void create_incorrect_public_key_throws_illegal_state() throws Exception {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        JwtProperties properties = properties(
                pem("PRIVATE KEY", source.toRSAPrivateKey().getEncoded()),
                incorrectKey());

        assertThatThrownBy(() -> factory.create(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("jwt.public-key");
    }

}