package org.extvos.auth.service.wechat;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * @author Mingcai SHEN
 */
@Configuration
public class WechatConfig {
    /* https://open.weixin.qq.com/connect/oauth2/authorize?
           appid=wx520c15f417810387
           &redirect_uri=https%3A%2F%2Fchong.qq.com%2Fphp%2Findex.php%3Fd%3D%26c%3DwxAdapter%26m%3DmobileDeal%26showwxpaytitle%3D1%26vb2ctag%3D4_2030_5_1194_60
           &response_type=code
           &scope=snsapi_base
           &state=123#wechat_redirect
     */
    /**
     *
     */
    @Value("${quick.auth.wechat.endpoint:https://open.weixin.qq.com/connect/oauth2/authorize}")
    private String endpoint;

    /**
     *
     */
    @Value("${quick.auth.wechat.app-id:}")
    private String appId;

    /**
     *
     */
    @Value("${quick.auth.wechat.app-secret:}")
    private String appSecret;

    /**
     *
     */
    @Value("${quick.auth.wechat.response-type:code}")
    private String responseType;

    /**
     *
     */
    @Value("${quick.auth.wechat.scope:snsapi_userinfo}")
    private String scope;

    /**
     *
     */
    @Value("${quick.auth.wechat.grant-type:authorization_code}")
    private String grantType;

    /**
     * token for verification
     */
    @Value("${quick.auth.wechat.token:quick-wechat}")
    private String token;

    public String getEndpoint() {
        return endpoint;
    }

    public String getAppId() {
        return appId;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getScope() {
        return scope;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getToken() {
        return token;
    }
}
