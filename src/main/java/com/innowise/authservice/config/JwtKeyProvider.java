package com.innowise.authservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import java.util.Map;

public class JwtKeyProvider {

    private final RSAKey jwk;

    public JwtKeyProvider(RSAKey jwk) {
        this.jwk = jwk;
    }

    public RSAKey signingKey() {
        return jwk;
    }

    public RSAKey publicKey() {
        return jwk.toPublicJWK();
    }

    public String keyId() {
        return jwk.getKeyID();
    }

    public Map<String, Object> publicJwkSet() {
        return new JWKSet(jwk.toPublicJWK()).toJSONObject();
    }
}
