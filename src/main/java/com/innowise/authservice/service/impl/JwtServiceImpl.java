package com.innowise.authservice.service.impl;


import com.innowise.authservice.config.JwtKeyProvider;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.service.JwtService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtServiceImpl implements JwtService {

    private final JwtKeyProvider keyProvider;
    private final Duration accessTokenExpiration;
    private final Duration refreshTokenExpiration;
    private static final Duration SERVICE_TOKEN_TTL = Duration.ofSeconds(60);

    public JwtServiceImpl(JwtKeyProvider keyProvider, JwtProperties properties) {
        this.keyProvider = keyProvider;
        this.accessTokenExpiration = properties.accessTokenExpiration();
        this.refreshTokenExpiration = properties.refreshTokenExpiration();
    }

    @Override
    public String generateAccessToken(Credential credential) {
        return sign(userClaims(credential, ACCESS_TOKEN_TYPE, accessTokenExpiration));
    }

    @Override
    public String generateRefreshToken(Credential credential) {
        return sign(userClaims(credential, REFRESH_TOKEN_TYPE, refreshTokenExpiration));
    }

    @Override
    public JWTClaimsSet parseAndValidate(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            if (!jwt.verify(new RSASSAVerifier(keyProvider.publicKey()))) {
                throw new BadCredentialsException("Token signature does not match");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();

            if (expiration == null || expiration.before(new Date())) {
                throw new BadCredentialsException("Token is expired");
            }
            return claims;
        } catch (ParseException | JOSEException e) {
            throw new BadCredentialsException("Token is malformed", e);
        }
    }

    @Override
    public void requireTokenType(JWTClaimsSet claims, String expectedType) {
        var actualTokenType = claims.getClaim(TOKEN_TYPE_CLAIM);
        if (!expectedType.equals(actualTokenType)) {
            throw new InvalidRefreshTokenException(
                    "Expected: " + expectedType + " token but got: " + actualTokenType
            );
        }
    }

    @Override
    public String generateServiceToken() {
        Instant now = Instant.now();
        return sign(new JWTClaimsSet.Builder()
                .subject(SERVICE_SUBJECT)
                .claim(ROLE_CLAIM, Role.ADMIN.name())
                .claim(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_TYPE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(SERVICE_TOKEN_TTL)))
                .build());
    }

    private JWTClaimsSet userClaims(Credential credential, String tokenType, Duration expiration) {
        Instant now = Instant.now();
        String userId = credential.getUserId().toString();
        return new JWTClaimsSet.Builder()
                .subject(userId)
                .claim(USER_ID_CLAIM, userId)
                .claim(ROLE_CLAIM, credential.getRole().name())
                .claim(TOKEN_TYPE_CLAIM, tokenType)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(expiration)))
                .build();
    }

    private String sign(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(keyProvider.keyId())
                            .build(),
                    claims);
            jwt.sign(new RSASSASigner(keyProvider.signingKey()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
    }
}
