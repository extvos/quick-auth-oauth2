package plus.extvos.auth.controller.wxapp;

import io.swagger.annotations.Api;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.auth.service.*;

@Api(tags = {"微信小程序认证"})
//@ConditionalOnProperty(prefix = "quick.auth.wxapp", name = "enabled", havingValue = "true")
//@RestController
@RequestMapping("/auth/oauth2/wxapp")
public class WxappAuthController {

    private static final Logger log = LoggerFactory.getLogger(WxappAuthController.class);

    @Value("${quick.auth.base-url:http://localhost}")
    private String baseUrl;

    @Value("${quick.auth.authorized-url:}")
    private String authorizedUrl;

    @Value("${quick.auth.base.auto-register:false}")
    private boolean autoRegister;

    @Autowired
    private WxappAuthConfig wxappAuthConfig;

    @Autowired
    private QuickAuthConfig quickAuthConfig;

    @Autowired
    private QuickAuthService quickAuthService;

    @Autowired
    private OpenIdResolver openidResolver;

    @Autowired(required = false)
    private QuickAuthCallback quickAuthCallback;

    @Autowired(required = false)
    private UserRegisterHook userRegisterHook;

    @Autowired
    private ProviderService providerService;

    @Autowired
    private QuickAuthentication quickAuthentication;

}
