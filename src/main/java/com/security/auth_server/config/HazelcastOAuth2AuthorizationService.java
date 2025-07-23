package com.security.auth_server.config;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


@Component
public class HazelcastOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final IMap<String, OAuth2Authorization> map;
    private final IMap<String, OAuth2Authorization> accessTokenValueToAuth;
    private final IMap<String, OAuth2Authorization> refreshTokenValueToAuth;

    public HazelcastOAuth2AuthorizationService(HazelcastInstance hazelcastInstance) {
        this.map = hazelcastInstance.getMap("auth-token-store");
        this.accessTokenValueToAuth = hazelcastInstance.getMap("access-to-auth");
        this.refreshTokenValueToAuth = hazelcastInstance.getMap("refresh-to-auth");
    }

    @Override
    public void save(OAuth2Authorization authorization) {


        Map<String,Object> tokenValueType = authorization.getAttributes();
        String tokenValue = "";
        String refreshTokenValue = "";
        for(String token : tokenValueType.keySet()){
            if(token.equalsIgnoreCase(Principal.class.getName()))
                continue;
            OAuth2TokenType type =(OAuth2TokenType) tokenValueType.get(token);
            if(type.getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue())) {
                tokenValue = token;

            }else if(type.getValue().equals(OAuth2TokenType.REFRESH_TOKEN.getValue())){
                refreshTokenValue = token;

            }
        }
        System.out.println("access token value "+tokenValue);
        map.put(authorization.getId(), authorization);
        accessTokenValueToAuth.put(tokenValue,authorization);
        refreshTokenValueToAuth.put(refreshTokenValue,authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        map.remove(authorization.getAccessToken().getToken().getTokenValue());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return map.get(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if(tokenType != null && tokenType.equals(OAuth2TokenType.ACCESS_TOKEN))
        return accessTokenValueToAuth.get(token);
        else if(tokenType != null && tokenType.equals(OAuth2TokenType.REFRESH_TOKEN))
            return refreshTokenValueToAuth.get(token);
        else
            return accessTokenValueToAuth.get(token);
    }

    private boolean tokenMatches(OAuth2Authorization auth, String token, OAuth2TokenType tokenType) {
        if (tokenType == null) return allTokens(auth).contains(token);
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType))
            return auth.getAccessToken() != null &&
                    auth.getAccessToken().getToken().getTokenValue().equals(token);
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType))
            return auth.getRefreshToken() != null &&
                    auth.getRefreshToken().getToken().getTokenValue().equals(token);
        return false;
    }

    private Set<String> allTokens(OAuth2Authorization auth) {
        Set<String> tokens = new HashSet<>();
        if (auth.getAccessToken() != null) tokens.add(auth.getAccessToken().getToken().getTokenValue());
        if (auth.getRefreshToken() != null) tokens.add(auth.getRefreshToken().getToken().getTokenValue());
        return tokens;
    }
}
