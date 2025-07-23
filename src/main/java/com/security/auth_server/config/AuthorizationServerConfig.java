package com.security.auth_server.config;

import com.hazelcast.core.HazelcastInstance;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {


@Bean
@Order(1)
public SecurityFilterChain authorizationServerSecurityFilterChain(
        HttpSecurity http,
        PasswordGrantAuthenticationProvider passwordGrantProvider,
        OAuth2PasswordAuthenticationConverter passwordConverter, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,OAuth2AuthorizationService oAuth2AuthorizationService) throws Exception {

    OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(oAuth2AuthorizationService,tokenGenerator);
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer();

    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, Customizer.withDefaults())
            .csrf(csrf -> csrf.disable()).
            securityContext(securityContext -> securityContext.securityContextRepository(new NullSecurityContextRepository()))
            .getConfigurer(org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.class)
            .tokenEndpoint(tokenEndpoint ->
            tokenEndpoint
                    .accessTokenRequestConverter(passwordConverter)
                    .authenticationProvider(refreshTokenAuthenticationProvider)
                    .authenticationProvider(passwordGrantProvider)
    ).tokenGenerator(tokenGenerator);

    return http.build();
}


    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(
                User.withUsername("user")
                        .password("{noop}pass")
                        .roles("USER")
                        .build()
        );
        return manager;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-id")
                .clientSecret("{noop}client-secret")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofHours(1))
                        .reuseRefreshTokens(true)
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }

    @Bean
    public AuthenticationManager authManager(CustomAuthenticationProvider customAuthProvider) {
        return new ProviderManager(customAuthProvider);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        return new DelegatingOAuth2TokenGenerator(
                new OAuth2AccessTokenGenerator(),
                new OAuth2RefreshTokenGenerator()
        );
    }
}
