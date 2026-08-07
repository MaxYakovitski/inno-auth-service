package com.innowise.authservice.config.jwk;

import com.innowise.authservice.controller.TestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;


class PemRsaKeyLoaderTest {

    private static final String KEY_ID = "test-key";

    private final PemRsaKeyLoader loader = new PemRsaKeyLoader();

    private static Resource pem(String label, byte[] der) {
        String content = "-----BEGIN %s-----%n%s%n-----END %s-----%n"
                .formatted(label, Base64.getMimeEncoder().encodeToString(der), label);
        return new ByteArrayResource(content.getBytes(StandardCharsets.UTF_8));
    }

    private static Resource incorrectKey() {
        return new ByteArrayResource("not-a-key".getBytes(StandardCharsets.UTF_8));
    }

    private static Resource unreadable() {
        return new FileSystemResource("no_file");
    }

    @Test
    void read_private_key_valid_pem_returns_key() throws Exception {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        RSAPrivateKey result = loader.readPrivateKey(pem("PRIVATE KEY", source.toRSAPrivateKey().getEncoded()));
        assertThat(result.getModulus()).isEqualTo(source.toRSAPrivateKey().getModulus());
    }

    @Test
    void read_public_key_valid_pem_returns_key() throws Exception {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        RSAPublicKey result = loader.readPublicKey(pem("PUBLIC KEY", source.toRSAPublicKey().getEncoded()));
        assertThat(result.getModulus()).isEqualTo(source.toRSAPublicKey().getModulus());
    }

    @Test
    void read_private_key_incorrect_content_throws_illegal_state() {
        Resource resource = incorrectKey();
        assertThatThrownBy(() -> loader.readPrivateKey(resource))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("jwt.private-key");
    }

    @Test
    void read_public_key_incorrect_content_throws_illegal_state() {
        Resource resource = incorrectKey();
        assertThatThrownBy(() -> loader.readPublicKey(resource))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("jwt.public-key");
    }

    @Test
    void read_private_key_unreadable_resource_throws_illegal_state() {
        Resource resource = unreadable();
        assertThatThrownBy(() -> loader.readPrivateKey(resource))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot read");
    }

}