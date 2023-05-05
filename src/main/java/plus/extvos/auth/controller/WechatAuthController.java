package plus.extvos.auth.controller;

import io.swagger.annotations.Api;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Api(tags = {"微信公众号认证"})
@ConditionalOnProperty(prefix = "quick.auth.wechat", name = "enabled", havingValue = "true")
@RestController
@RequestMapping("/auth/oauth2/wechat")
public class WechatAuthController {
}
