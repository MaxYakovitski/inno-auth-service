package com.innowise.authservice.service.impl;


import com.innowise.authservice.config.JwtKeyProvider;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

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
        return buildToken(credential, ACCESS_TOKEN_TYPE, accessTokenExpiration);
    }

    @Override
    public String generateRefreshToken(Credential credential) {
        return buildToken(credential, REFRESH_TOKEN_TYPE, refreshTokenExpiration);
    }

    private String buildToken(Credential credential, String tokenType, Duration expiration) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .subject(credential.getUserId().toString())
                .claim(USER_ID_CLAIM, credential.getUserId().toString())
                .claim(ROLE_CLAIM, credential.getRole().name())
                .claim(TOKEN_TYPE_CLAIM, tokenType)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(expiration)))
                .signWith(keyProvider.privateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public Claims parseAndValidate(String token) {
        return Jwts.parser()
                .verifyWith(keyProvider.publicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @Override
    public void requireTokenType(Claims claims, String expectedType) {
        var actualTokenType = claims.get(TOKEN_TYPE_CLAIM, String.class);
        if (!expectedType.equals(actualTokenType)) {
            throw new InvalidRefreshTokenException(
                    "Expected: " + expectedType + " token but got: " + actualTokenType
            );
        }
    }

    @Override
    public String generateServiceToken() {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .subject(SERVICE_SUBJECT)
                .claim(ROLE_CLAIM, Role.ADMIN.name())
                .claim(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_TYPE)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(SERVICE_TOKEN_TTL)))
                .signWith(keyProvider.privateKey(), Jwts.SIG.RS256)
                .compact();
    }
}
