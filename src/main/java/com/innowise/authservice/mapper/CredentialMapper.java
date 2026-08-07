package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.credential.CredentialCreateDto;
import com.innowise.authservice.dto.credential.CredentialResponseDto;
import com.innowise.authservice.entity.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

import java.util.UUID;

@Mapper(componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CredentialMapper {

    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "username", source = "dto.email")
    @Mapping(target = "passwordHash", source = "passwordHash")
    @Mapping(target = "role", constant = "USER")
    @Mapping(target = "active", constant = "true")
    Credential toEntity(CredentialCreateDto dto, UUID userId, String passwordHash);

    CredentialResponseDto toDto(Credential entity);
}
