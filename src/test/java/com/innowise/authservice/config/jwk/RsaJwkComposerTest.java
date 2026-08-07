package com.innowise.authservice.config.jwk;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.controller.TestKeys;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RsaJwkComposerTest {

    private static final String KEY_ID = "test-key";

    private final Resource privateResource = new ByteArrayResource("private".getBytes());
    private final Resource publicResource = new ByteArrayResource("public".getBytes());

    @Mock
    private PemRsaKeyLoader keyLoader;
    @Mock
    private RsaKeyPairGenerator keyGenerator;
    @Mock
    private JwkMetadata metadata;
    @Mock
    private RSAKey finalKey;

    @Test
    void compose_configured_keys_reads_from_pem() throws JOSEException {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        JwtProperties properties = new JwtProperties(privateResource, publicResource, KEY_ID,
                Duration.ofMinutes(15), Duration.ofDays(7));
        RsaJwkComposer composer = new RsaJwkComposer(properties, keyLoader, keyGenerator, metadata);

        when(keyLoader.readPublicKey(publicResource)).thenReturn(source.toRSAPublicKey());
        when(keyLoader.readPrivateKey(privateResource)).thenReturn(source.toRSAPrivateKey());
        when(metadata.apply(any(RSAKey.Builder.class), eq(KEY_ID))).thenReturn(finalKey);

        RSAKey result = composer.compose();

        assertThat(result).isSameAs(finalKey);
        verify(keyGenerator, never()).generate();
    }

    @Test
    void compose_missing_keys_generates_new_pair() {
        RSAKey source = TestKeys.rsaJwk(KEY_ID);
        JwtProperties properties = new JwtProperties(null, null, KEY_ID,
                Duration.ofMinutes(15), Duration.ofDays(7));
        RsaJwkComposer composer = new RsaJwkComposer(properties, keyLoader, keyGenerator, metadata);

        when(keyGenerator.generate()).thenReturn(source);
        when(metadata.apply(any(RSAKey.Builder.class), eq(KEY_ID))).thenReturn(finalKey);

        RSAKey result = composer.compose();

        assertThat(result).isSameAs(finalKey);
        verifyNoInteractions(keyLoader);
    }

}