package com.security.auth_server.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

@Component
public class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grant = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"password".equals(grant)) return null;
        return new PasswordGrantAuthenticationToken(
                request.getParameter(OAuth2ParameterNames.USERNAME),
                request.getParameter(OAuth2ParameterNames.PASSWORD),
                Set.of(Optional.ofNullable(request.getParameter(OAuth2ParameterNames.SCOPE)).orElse("").split("\\s+"))
        );
    }
}
