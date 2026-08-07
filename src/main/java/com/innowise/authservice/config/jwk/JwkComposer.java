package com.innowise.authservice.config.jwk;


import com.nimbusds.jose.jwk.RSAKey;

public interface JwkComposer {

    RSAKey compose();
}
