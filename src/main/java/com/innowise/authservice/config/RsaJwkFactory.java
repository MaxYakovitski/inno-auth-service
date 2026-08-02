package com.innowise.authservice.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


@Component
public class RsaJwkFactory {

    private static final int GENERATED_KEY_SIZE = 2048;

    public RSAKey create(JwtProperties properties) {
        if (exists(properties.privateKey()) && exists(properties.publicKey())) {
            return readFromPem(properties);
        }
        return generate(properties.keyId());
    }

    private static boolean exists(Resource resource) {
        return resource != null && resource.exists();
    }

    private RSAKey readFromPem(JwtProperties properties) {
        RSAPublicKey publicKey = readPublicKey(properties.publicKey());
        RSAPrivateKey privateKey = readPrivateKey(properties.privateKey());

        return withMetadata(
                new RSAKey.Builder(publicKey).privateKey(privateKey),
                properties.keyId());
    }

    private RSAKey generate(String keyId) {
        try {
            RSAKey generated = new RSAKeyGenerator(GENERATED_KEY_SIZE).generate();
            return withMetadata(new RSAKey.Builder(generated), keyId);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate RSA key pair", e);
        }
    }

    private static RSAKey withMetadata(RSAKey.Builder builder, String keyId) {
        builder.keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256);
        try {
            return StringUtils.hasText(keyId)
                    ? builder.keyID(keyId).build()
                    : builder.keyIDFromThumbprint().build();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot compute key thumbprint", e);
        }
    }

    private static RSAPrivateKey readPrivateKey(Resource resource) {
        try (InputStream in = resource.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(in);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("jwt.private-key is not a valid PKCS#8 RSA key", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + resource.getDescription(), e);
        }
    }

    private static RSAPublicKey readPublicKey(Resource resource) {
        try (InputStream in = resource.getInputStream()) {
            return RsaKeyConverters.x509().convert(in);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("jwt.public-key is not a valid X.509 RSA key", e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + resource.getDescription(), e);
        }
    }
}
