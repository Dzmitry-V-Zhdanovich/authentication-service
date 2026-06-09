package com.innowise.authenticationservice.mapper;

import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.model.Credential;
import com.innowise.authenticationservice.model.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;
import org.mapstruct.ReportingPolicy;

import java.util.UUID;

@Mapper(componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface CredentialMapper {

    @Mapping(target = "login", source = "request.login")
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "passwordHash", source = "encodedPassword")
    @Mapping(target = "role", source = "role")
    Credential toEntity(RegisterUserRequest request, UUID userId, String encodedPassword, Role role);
}
