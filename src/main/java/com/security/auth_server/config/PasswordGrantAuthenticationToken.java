package com.security.auth_server.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Set;

public class PasswordGrantAuthenticationToken extends AbstractAuthenticationToken {
    private final String username, password;
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(String u, String p, Set<String> scopes) {
        super(null);
        this.username = u; this.password = p;
        this.scopes = scopes; setAuthenticated(false);
    }

    @Override public Object getCredentials() { return password; }
    @Override public Object getPrincipal()   { return username; }
    public Set<String> getScopes()           { return scopes; }
}
