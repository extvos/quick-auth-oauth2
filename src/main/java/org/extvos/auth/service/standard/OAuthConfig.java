package org.extvos.auth.service.standard;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * @author Mingcai SHEN
 */
@Configuration
public class OAuthConfig {
    @Value("${quick.auth.oauth2.endpoint:}")
    private String endpoint;

    @Value("${quick.auth.oauth2.client-id:}")
    private String clientId;

    @Value("${quick.auth.oauth2.secret:}")
    private String secret;

    @Value("${quick.auth.oauth2.scope:read:}")
    private String scope;

    public String getEndpoint() {
        return endpoint;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSecret() {
        return secret;
    }

    public String getScope() {
        return scope;
    }

}
