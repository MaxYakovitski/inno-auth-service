package com.innowise.authservice.config.jwk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JwkMetadata {

    public RSAKey apply(RSAKey.Builder builder, String keyId) {
        builder.keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256);
        try {
            return StringUtils.hasText(keyId)
                    ? builder.keyID(keyId).build()
                    : builder.keyIDFromThumbprint().build();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot compute key thumbprint", e);
        }
    }
}
