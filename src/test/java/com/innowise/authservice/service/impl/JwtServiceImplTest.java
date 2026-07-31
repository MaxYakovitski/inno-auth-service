package com.innowise.authservice.service.impl;

import com.innowise.authservice.config.JwtKeyProvider;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

    @BeforeEach
    void setUp() {

        JwtProperties properties = properties(ACCESS_TTL);
        keyProvider = new JwtKeyProvider(properties);
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

    private static JwtProperties properties(Duration accessTtl) {
        return new JwtProperties(null, null, KEY_ID, accessTtl, REFRESH_TTL);
    }

    @Test
    void generateAccessToken_contains_correctClaims() {
        String token = jwtService.generateAccessToken(credential);
        Claims claims = jwtService.parseAndValidate(token);

        assertThat(claims.getSubject()).isEqualTo(credential.getUserId().toString());
        assertThat(claims.get(JwtService.USER_ID_CLAIM, String.class))
                .isEqualTo(credential.getUserId().toString());
        assertThat(claims.get(JwtService.ROLE_CLAIM, String.class))
                .isEqualTo(Role.USER.name());
        assertThat(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class))
                .isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
    }

    @Test
    void generateAccessToken_is_signed_with_rs256_and_has_keyId() {
        String token = jwtService.generateAccessToken(credential);

        var header = Jwts.parser()
                .verifyWith(keyProvider.publicKey())
                .build()
                .parseSignedClaims(token)
                .getHeader();

        assertThat(header.getAlgorithm()).isEqualTo("RS256");
        assertThat(header.getKeyId()).isEqualTo(KEY_ID);
    }

    @Test
    void token_is_verifiable_with_publicKey() {
        String token = jwtService.generateAccessToken(credential);

        assertThatCode(() -> Jwts.parser()
                .verifyWith(keyProvider.publicKey())
                .build()
                .parseSignedClaims(token))
                .doesNotThrowAnyException();
    }

    @Test
    void token_signed_with_anotherKey_is_rejected() {
        String foreignToken = new JwtServiceImpl(new JwtKeyProvider(properties(ACCESS_TTL)), properties(ACCESS_TTL))
                .generateAccessToken(credential);

        assertThatThrownBy(() -> jwtService.parseAndValidate(foreignToken))
                .isInstanceOf(SignatureException.class);
    }

    @Test
    void expiredToken_throws_expiredJwtException() {
        JwtProperties expired = properties(Duration.ofSeconds(-1));
        JwtServiceImpl service = new JwtServiceImpl(new JwtKeyProvider(expired), expired);
        String token = service.generateAccessToken(credential);

        assertThatThrownBy(() -> service.parseAndValidate(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void generate_refreshToken_with_refreshType() {
        String token = jwtService.generateRefreshToken(credential);
        Claims claims = jwtService.parseAndValidate(token);

        assertThat(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class))
                .isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
    }

    @Test
    void requireTokenType_passes_when_type_matches() {
        Claims claims = jwtService.parseAndValidate(jwtService.generateAccessToken(credential));

        assertThatCode(() -> jwtService.requireTokenType(claims, JwtService.ACCESS_TOKEN_TYPE))
                .doesNotThrowAnyException();
    }

    @Test
    void requireTokenType_throws_when_type_not_match() {
        Claims claims = jwtService.parseAndValidate(jwtService.generateAccessToken(credential));

        assertThatThrownBy(() -> jwtService.requireTokenType(claims, JwtService.REFRESH_TOKEN_TYPE))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void generateServiceToken_carriesAdminRoleAndExpiresQuickly() {
        Claims claims = jwtService.parseAndValidate(jwtService.generateServiceToken());

        assertThat(claims.getSubject()).isEqualTo(JwtService.SERVICE_SUBJECT);
        assertThat(claims.get(JwtService.ROLE_CLAIM, String.class)).isEqualTo(Role.ADMIN.name());
        assertThat(claims.get(JwtService.TOKEN_TYPE_CLAIM, String.class))
                .isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
        assertThat(claims.get(JwtService.USER_ID_CLAIM)).isNull();

        assertThat(claims.getExpiration().toInstant())
                .isBefore(Instant.now().plusSeconds(61));
    }

}