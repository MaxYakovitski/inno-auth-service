package com.innowise.authservice.controller;

import com.innowise.authservice.dto.credential.*;
import com.innowise.authservice.dto.credential.TokenDto;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<CredentialResponseDto> register(@Valid @RequestBody CredentialCreateDto request) {
        var response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@Valid @RequestBody CredentialLoginDto request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenDto> refresh(@Valid @RequestBody CredentialRefreshDto request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

}
