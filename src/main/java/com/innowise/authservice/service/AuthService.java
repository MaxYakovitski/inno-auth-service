package com.innowise.authservice.service;


import com.innowise.authservice.dto.credential.*;
import com.innowise.authservice.dto.credential.TokenDto;

public interface AuthService {

    CredentialResponseDto register(CredentialCreateDto request);
    TokenDto login(CredentialLoginDto request);
    TokenDto refresh(CredentialRefreshDto request);

}
