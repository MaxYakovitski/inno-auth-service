package com.innowise.authservice.service;


import com.innowise.authservice.entity.Credential;
import com.nimbusds.jwt.JWTClaimsSet;

public interface JwtService {

    String USER_ID_CLAIM = "user_id";
    String ROLE_CLAIM = "role";

    String TOKEN_TYPE_CLAIM = "type";
    String ACCESS_TOKEN_TYPE = "access";
    String REFRESH_TOKEN_TYPE = "refresh";

    String SERVICE_SUBJECT = "auth-service";

    String generateAccessToken(Credential credential);
    String generateRefreshToken(Credential credential);
    String generateServiceToken();

    JWTClaimsSet parseAndValidate(String token);

    void requireTokenType(JWTClaimsSet claims, String expectedType);
}
