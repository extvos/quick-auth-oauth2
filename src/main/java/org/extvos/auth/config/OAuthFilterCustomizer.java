package org.extvos.auth.config;

import org.extvos.auth.service.QuickFilterCustomizer;
import org.springframework.context.annotation.Configuration;

/**
 * @author Mingcai SHEN
 */
@Configuration
public class OAuthFilterCustomizer implements QuickFilterCustomizer {
    private String ctxPath = System.getProperty("server.servlet.context-path") == null ? "" : System.getProperty("server.servlet.context-path");

    @Override
    public String[] anons() {
        return new String[]{
                ctxPath + "/" + "auth/oauth/**"
        };
    }

    @Override
    public String[] auths() {
        return new String[0];
    }
}
