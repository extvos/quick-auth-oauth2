package plus.extvos.auth.controller.wechat;

import io.swagger.annotations.Api;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.auth.service.*;

@Api(tags = {"微信公众号认证"})
//@ConditionalOnProperty(prefix = "quick.auth.wechat", name = "enabled", havingValue = "true")
//@RestController
@RequestMapping("/auth/oauth2/wechat")
public class WechatAuthController {

    @Autowired
    private WechatAuthConfig wechatAuthConfig;

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
