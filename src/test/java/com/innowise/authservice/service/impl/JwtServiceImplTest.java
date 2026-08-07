package com.innowise.authservice.service.impl;

import com.innowise.authservice.config.JwtKeyProvider;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.controller.TestKeys;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.service.JwtService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;


class JwtServiceImplTest {

    private static final String KEY_ID = "test-key";
    private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TTL = Duration.ofDays(7);

    private JwtKeyProvider keyProvider;
    private JwtServiceImpl jwtService;
    private Credential credential;

    private static JwtProperties properties(Duration accessTtl) {
        return new JwtProperties(null, null, KEY_ID, accessTtl, REFRESH_TTL);
    }

    private JWTClaimsSet accessTokenClaims() {
        return jwtService.parseAndValidate(jwtService.generateAccessToken(credential));
    }

    @BeforeEach
    void setUp() {

        JwtProperties properties = properties(ACCESS_TTL);
        keyProvider = new JwtKeyProvider(TestKeys.rsaJwk(KEY_ID));
        jwtService = new JwtServiceImpl(keyProvider, properties);

        credential = Credential.builder()
                .id(UUID.randomUUID())
                .userId(UUID.randomUUID())
                .username("m@test.com")
                .passwordHash("my_password")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void generate_access_token_contains_correct_claims() {
        JWTClaimsSet claims = accessTokenClaims();

        assertThat(claims.getSubject()).isEqualTo(credential.getUserId().toString());
        assertThat(claims.getClaim(JwtService.USER_ID_CLAIM))
                .isEqualTo(credential.getUserId().toString());
        assertThat(claims.getClaim(JwtService.ROLE_CLAIM))
                .isEqualTo(Role.USER.name());
        assertThat(claims.getClaim(JwtService.TOKEN_TYPE_CLAIM))
                .isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
    }

    @Test
    void generate_access_token_is_signed_with_rs256_and_has_key_id() throws ParseException {
        SignedJWT jwt = SignedJWT.parse(jwtService.generateAccessToken(credential));

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(KEY_ID);
    }

    @Test
    void token_is_verifiable_with_public_key() throws Exception {
        SignedJWT jwt = SignedJWT.parse(jwtService.generateAccessToken(credential));
        assertThat(jwt.verify(new RSASSAVerifier(keyProvider.publicKey()))).isTrue();
    }

    @Test
    void token_signed_with_another_key_is_rejected() {
        String foreignToken = new JwtServiceImpl(
                new JwtKeyProvider(TestKeys.rsaJwk(KEY_ID)),
                properties(ACCESS_TTL)
        ).generateAccessToken(credential);

        assertThatThrownBy(() -> jwtService.parseAndValidate(foreignToken))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void expired_token_throws_expired_jwt_exception() {
        JwtProperties expired = properties(Duration.ofSeconds(-1));
        JwtServiceImpl service = new JwtServiceImpl(new JwtKeyProvider(TestKeys.rsaJwk(KEY_ID)), expired);
        String token = service.generateAccessToken(credential);

        assertThatThrownBy(() -> service.parseAndValidate(token))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void generate_refresh_token_with_refresh_type() {
        JWTClaimsSet claims = jwtService.parseAndValidate(jwtService.generateRefreshToken(credential));

        assertThat(claims.getClaim(JwtService.TOKEN_TYPE_CLAIM))
                .isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
    }

    @Test
    void require_token_type_passes_when_type_matches() {
        JWTClaimsSet claims = accessTokenClaims();
        assertThatCode(() -> jwtService.requireTokenType(claims, JwtService.ACCESS_TOKEN_TYPE))
                .doesNotThrowAnyException();
    }

    @Test
    void require_token_type_throws_when_type_not_match() {
        JWTClaimsSet claims = accessTokenClaims();
        assertThatThrownBy(() -> jwtService.requireTokenType(claims, JwtService.REFRESH_TOKEN_TYPE))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void generate_service_token_carries_admin_role_and_expires_quickly() {
        JWTClaimsSet claims = jwtService.parseAndValidate(jwtService.generateServiceToken());

        assertThat(claims.getSubject()).isEqualTo(JwtService.SERVICE_SUBJECT);
        assertThat(claims.getClaim(JwtService.ROLE_CLAIM)).isEqualTo(Role.ADMIN.name());
        assertThat(claims.getClaim(JwtService.TOKEN_TYPE_CLAIM))
                .isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
        assertThat(claims.getClaim(JwtService.USER_ID_CLAIM)).isNull();
        assertThat(claims.getExpirationTime().toInstant())
                .isBefore(Instant.now().plusSeconds(61));
    }

}