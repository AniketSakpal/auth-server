package com.security.auth_server.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.security.Principal;

@Component
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authSvc;
    private final RegisteredClientRepository clients;
    private final AuthenticationManager authManager;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    public PasswordGrantAuthenticationProvider(
            OAuth2AuthorizationService authSvc,
            RegisteredClientRepository clients,
            AuthenticationManager authMgr,
            OAuth2TokenGenerator<?> tg
    ) {
        this.authSvc = authSvc; this.clients = clients;
        this.authManager = authMgr; this.tokenGenerator = tg;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken authReq = (PasswordGrantAuthenticationToken) authentication;

        Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();

        RegisteredClient client = clients.findByClientId("client-id"); // require to make it dynamic

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(userAuth)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authReq.getScopes())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .authorizationGrant(new UsernamePasswordAuthenticationToken(authReq.getName(), authReq.getCredentials()))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        System.out.println(context != null);
        System.out.println(tokenGenerator.generate(context));
        // token generation

        OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(context);
        System.out.println(accessToken);
        OAuth2RefreshToken refreshToken = (OAuth2RefreshToken) tokenGenerator.generate(
                DefaultOAuth2TokenContext.builder()
                        .registeredClient(client)
                        .principal(userAuth)
                        .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                        .authorizedScopes(authReq.getScopes())
                        .authorizationGrantType(new AuthorizationGrantType("password"))
                        .authorizationGrant(new UsernamePasswordAuthenticationToken(authReq.getName(), authReq.getCredentials()))
                        .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                        .build()
        );
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(authReq.getName())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .attributes(map -> {
                    map.put(accessToken.getTokenValue(),OAuth2TokenType.ACCESS_TOKEN);
                    map.put(refreshToken.getTokenValue(),OAuth2TokenType.REFRESH_TOKEN);})
                .attribute(Principal.class.getName(),userAuth)
                .build();

        OAuth2AccessTokenAuthenticationToken finalResponse = new OAuth2AccessTokenAuthenticationToken(client, userAuth, accessToken, refreshToken);
        authSvc.save(authorization);

        return finalResponse;
    }

    @Override public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
