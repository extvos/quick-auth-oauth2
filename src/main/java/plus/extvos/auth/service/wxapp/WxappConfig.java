package plus.extvos.auth.service.wxapp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * @author Mingcai SHEN
 */
@Configuration
public class WxappConfig {
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
    @Value("${quick.auth.wxapp.endpoint:https://open.weixin.qq.com/connect/oauth2/authorize}")
    private String endpoint;

    /**
     *
     */
    @Value("${quick.auth.wxapp.app-id:}")
    private String appId;

    /**
     *
     */
    @Value("${quick.auth.wxapp.app-secret:}")
    private String appSecret;

    /**
     *
     */
    @Value("${quick.auth.wxapp.response-type:code}")
    private String responseType;

    /**
     *
     */
    @Value("${quick.auth.wxapp.scope:snsapi_base}")
    private String scope;

    /**
     *
     */
    @Value("${quick.auth.wxapp.grant-type:authorization_code}")
    private String grantType;

    /**
     * token for verification
     */
    @Value("${quick.auth.wxapp.token:quick-wechat}")
    private String token;

    @Value("${quick.auth.wxapp.union:false}")
    private Boolean union;

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

    public Boolean getUnion() {
        return union != null && union;
    }

    public void setUnion(Boolean union) {
        this.union = union;
    }
}
