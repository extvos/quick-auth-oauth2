package plus.extvos.auth.service.standard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import plus.extvos.auth.dto.OAuthState;
import plus.extvos.auth.service.OAuthProvider;
import plus.extvos.common.Assert;
import plus.extvos.common.exception.ResultException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

/**
 * @author Mingcai SHEN
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
    public Object notify(Map<String, Object> params, byte[] body) throws ResultException {
        log.debug("notify:> {} / {}", params, body != null ? body.length : 0);
        Assert.notEmpty(params, ResultException.badRequest("invalid request"));
        return null;
    }

    @Override
    public String getCodeUrl(String state, String redirectUri) throws ResultException {
        Assert.notEmpty(config.getClientId(), ResultException.internalServerError("oauth2 client can not be empty"));
        Assert.notEmpty(config.getSecret(), ResultException.internalServerError("oauth2 secret can not be empty"));
        Assert.notEmpty(config.getEndpoint(), ResultException.internalServerError("oauth2 endpoint can not be empty"));
        Assert.notEmpty(config.getScope(), ResultException.internalServerError("oauth2 scope can not be empty"));
        String s = null;
        try {
            s = config.getEndpoint() +
                    "?clientId=" + config.getClientId() +
                    "&response_type=code" +
                    "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
                    "&state=" + state +
                    "&scope=" + config.getScope();
        } catch (UnsupportedEncodingException e) {
            throw ResultException.internalServerError("url encode failed");
        }
        return s;
    }

    @Override
    public String resultPage(int ret, String message, String siteName) {
        return "";
    }

    @Override
    public String confirmPage(String title, String siteName, String gotoUrl) {
        return null;
    }

    @Override
    public OAuthState authorized(String code, String state, String via, OAuthState authState) throws ResultException {
        return null;
    }

    @Override
    public OAuthState authorizeUpdate(Map<String, Object> params, OAuthState authState) throws ResultException {
        return null;
    }

}
