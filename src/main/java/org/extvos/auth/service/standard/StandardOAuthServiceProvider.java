package org.extvos.auth.service.standard;

import org.extvos.auth.entity.OAuthState;
import org.extvos.auth.service.OAuthProvider;
import org.extvos.restlet.Assert;
import org.extvos.restlet.exception.RestletException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

/**
 * @author shenmc
 */
@Service
public class StandardOAuthServiceProvider implements OAuthProvider {
    private static final Logger log = LoggerFactory.getLogger(StandardOAuthServiceProvider.class);
    @Autowired
    private OAuthConfig config;

    public final static String SLUG = "oauth2";

    @Autowired
    public StandardOAuthServiceProvider(OAuthConfig cfg) {
        config = cfg;
    }

    @Override
    public String getSlug() {
        return SLUG;
    }

    @Override
    public String getName() {
        return "单点登录";
    }

    @Override
    public boolean redirectSupported() {
        return true;
    }

    @Override
    public Object notify(Map<String, Object> params, byte[] body) throws RestletException {
        log.debug("notify:> {} / {}", params, body != null ? body.length : 0);
        Assert.notEmpty(params, RestletException.badRequest("invalid request"));
        return null;
    }

    @Override
    public String getCodeUrl(String state, String redirectUri) throws RestletException {
        Assert.notEmpty(config.getClientId(), RestletException.internalServerError("oauth2 client can not be empty"));
        Assert.notEmpty(config.getSecret(), RestletException.internalServerError("oauth2 secret can not be empty"));
        Assert.notEmpty(config.getEndpoint(), RestletException.internalServerError("oauth2 endpoint can not be empty"));
        Assert.notEmpty(config.getScope(), RestletException.internalServerError("oauth2 scope can not be empty"));
        String s = null;
        try {
            s = config.getEndpoint() +
                    "?clientId=" + config.getClientId() +
                    "&response_type=code" +
                    "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
                    "&state=" + state +
                    "&scope=" + config.getScope();
        } catch (UnsupportedEncodingException e) {
            throw RestletException.internalServerError("url encode failed");
        }
        return s;
    }

    @Override
    public OAuthState authorized(String code, String state, String via, OAuthState authState) throws RestletException {
        return null;
    }

    @Override
    public OAuthState authorizeUpdate(Map<String, Object> params, OAuthState authState) throws RestletException {
        return null;
    }

}
