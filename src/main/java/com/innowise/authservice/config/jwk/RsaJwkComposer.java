package com.innowise.authservice.config.jwk;


import com.innowise.authservice.config.JwtProperties;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;


@Component
@RequiredArgsConstructor
public class RsaJwkComposer implements  JwkComposer {

    private final JwtProperties properties;
    private final PemRsaKeyLoader keyLoader;
    private final RsaKeyPairGenerator keyGenerator;
    private final JwkMetadata metadata;

    @Override
    public RSAKey compose() {
        RSAKey.Builder builder = hasConfiguredKeys() ? fromPem() : fromGenerated();
        return metadata.apply(builder, properties.keyId());
    }

    private boolean hasConfiguredKeys() {
        return exists(properties.privateKey()) && exists(properties.publicKey());
    }

    private static boolean exists(Resource resource) {
        return resource != null && resource.exists();
    }

    private RSAKey.Builder fromPem() {
        return new RSAKey.Builder(keyLoader.readPublicKey(properties.publicKey()))
                .privateKey(keyLoader.readPrivateKey(properties.privateKey()));
    }

    private RSAKey.Builder fromGenerated() {
        return new RSAKey.Builder(keyGenerator.generate());
    }
}
