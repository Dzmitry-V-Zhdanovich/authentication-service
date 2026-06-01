package com.innowise.authenticationservice.mapper;

import com.innowise.authenticationservice.dto.request.CreateUserInUserServiceRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring",
        unmappedTargetPolicy = ReportingPolicy.IGNORE,
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface UserMapper {

    @Mapping(source = "firstName", target = "name")
    @Mapping(source = "lastName", target = "surname")
    CreateUserInUserServiceRequest toCreateUserRequest(RegisterUserRequest request);
}
