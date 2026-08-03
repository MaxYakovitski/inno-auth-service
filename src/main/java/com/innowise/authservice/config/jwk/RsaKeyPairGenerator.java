package com.innowise.authservice.config.jwk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;


@Component
public class RsaKeyPairGenerator {

    private static final int GENERATED_KEY_SIZE = 2048;

    public RSAKey generate() {
        try {
            return new RSAKeyGenerator(GENERATED_KEY_SIZE).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate RSA key pair", e);
        }
    }

}
