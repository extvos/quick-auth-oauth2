package plus.extvos.auth.dto;

import java.io.Serializable;

public class OAuth2Config implements Serializable {
    private String name;
    private String clientId;
    private String clientSecret;
    private String authEndpoint;
    private String tokenEndpoint;
    private String userEndpoint;
    private String scope;
    private String userIdentifier;
    private String userDisplayName;
    private String userAvatar;

    public OAuth2Config() {

    }

    public static boolean validate(OAuth2Config cfg) {
        if (null == cfg) {
            return false;
        }
        return cfg.validate();
    }

    public boolean validate() {
        if (name == null || name.isEmpty()) {
            return false;
        } else if (clientId == null || clientId.isEmpty()) {
            return false;
        } else if (clientSecret == null || clientSecret.isEmpty()) {
            return false;
        } else if (authEndpoint == null || authEndpoint.isEmpty()) {
            return false;
        } else if (tokenEndpoint == null || tokenEndpoint.isEmpty()) {
            return false;
        } else if (userEndpoint == null || userEndpoint.isEmpty()) {
            return false;
        } else if (scope == null || scope.isEmpty()) {
            return false;
        } else if (userIdentifier == null || userIdentifier.isEmpty()) {
            return false;
        }

        return true;
    }

    public String getName() {
        return name;
    }

    public OAuth2Config setName(String name) {
        this.name = name;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public OAuth2Config setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public OAuth2Config setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public String getAuthEndpoint() {
        return authEndpoint;
    }

    public OAuth2Config setAuthEndpoint(String authEndpoint) {
        this.authEndpoint = authEndpoint;
        return this;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public OAuth2Config setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public String getUserEndpoint() {
        return userEndpoint;
    }

    public OAuth2Config setUserEndpoint(String userEndpoint) {
        this.userEndpoint = userEndpoint;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public OAuth2Config setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getUserIdentifier() {
        return userIdentifier;
    }

    public OAuth2Config setUserIdentifier(String userIdentifier) {
        this.userIdentifier = userIdentifier;
        return this;
    }

    public String getUserDisplayName() {
        return userDisplayName;
    }

    public OAuth2Config setUserDisplayName(String userDisplayName) {
        this.userDisplayName = userDisplayName;
        return this;
    }

    public String getUserAvatar() {
        return userAvatar;
    }

    public OAuth2Config setUserAvatar(String userAvatar) {
        this.userAvatar = userAvatar;
        return this;
    }
}
