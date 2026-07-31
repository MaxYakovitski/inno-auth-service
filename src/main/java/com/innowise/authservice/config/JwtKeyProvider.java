package com.innowise.authservice.config;

import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.RsaPublicJwk;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@Slf4j
public class JwtKeyProvider {

    private static final int GENERATED_KEY_SIZE = 2048;
    private static final String PEM_MARKERS = "-----(BEGIN|END)[^-]*-----";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final RsaPublicJwk publicJwk;

    public JwtKeyProvider(JwtProperties properties) {
        KeyPair keyPair = resolveKeyPair(properties);
        this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey = (RSAPublicKey) keyPair.getPublic();
        this.publicJwk = buildPublicJwk((RSAPublicKey) keyPair.getPublic(), properties.keyId());
        log.info("JWT signing key ready, kid={}", publicJwk.getId());
    }

    public RSAPrivateKey privateKey() {
        return privateKey;
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public String keyId() {
        return publicJwk.getId();
    }

    public JwkSet publicJwkSet() {
        return Jwks.set().add(publicJwk).build();
    }

    private static RsaPublicJwk buildPublicJwk(RSAPublicKey key, String configuredKeyId) {
        var builder = Jwks.builder()
                .key(key)
                .algorithm("RS256")
                .publicKeyUse("sig");

        if (StringUtils.hasText(configuredKeyId)) {
            builder.id(configuredKeyId);
        } else {
            builder.idFromThumbprint();
        }
        return builder.build();
    }

    private static KeyPair resolveKeyPair(JwtProperties properties) {
        if (StringUtils.hasText(properties.privateKey()) && StringUtils.hasText(properties.publicKey())) {
            return new KeyPair(readPublicKey(properties.publicKey()), readPrivateKey(properties.privateKey()));
        }
        return generateKeyPair();
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(GENERATED_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is not available", e);
        }
    }

    private static RSAPrivateKey readPrivateKey(String pem) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(decode(pem)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("jwt.private-key is not valid", e);
        }
    }

    private static RSAPublicKey readPublicKey(String pem) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decode(pem)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("jwt.public-key is not valid", e);
        }
    }

    private static byte[] decode(String key) {
        String base64 = key.replaceAll(PEM_MARKERS, "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
