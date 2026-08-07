package com.innowise.authservice.config.jwk;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class PemRsaKeyLoader {

    public RSAPrivateKey readPrivateKey(Resource resource) {
        return read(
                resource,
                RsaKeyConverters.pkcs8(),
                "jwt.private-key is not a valid PKCS#8 RSA key");
    }

    public RSAPublicKey readPublicKey(Resource resource) {
        return read(
                resource,
                RsaKeyConverters.x509(),
                "jwt.public-key is not a valid X.509 RSA key");
    }

    private static <T> T read (Resource resource, Converter<InputStream, T> converter, String message) {
        try (InputStream in = resource.getInputStream()) {
            return converter.convert(in);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(message, e);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + resource.getDescription(), e);
        }
    }
}
