package com.innowise.authservice.dto.user;


import java.time.LocalDate;

public record UserCreateDto(
        String name,
        String surname,
        LocalDate birthDate,
        String email
) {}
