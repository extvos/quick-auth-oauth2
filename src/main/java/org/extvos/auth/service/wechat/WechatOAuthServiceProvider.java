package org.extvos.auth.service.wechat;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpStatus;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.extvos.auth.controller.OAuthController;
import org.extvos.auth.enums.AuthCode;
import org.extvos.auth.service.OAuthProvider;
import org.extvos.common.utils.QuickHash;
import org.extvos.restlet.Assert;
import org.extvos.restlet.exception.RestletException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

/**
 * @author shenmc
 */
@Service
public class WechatOAuthServiceProvider implements OAuthProvider {

    private static final Logger log = LoggerFactory.getLogger(WechatOAuthServiceProvider.class);
    public static final String SLUG = "wechat";

    @Autowired
    private WechatConfig config;

    @Autowired
    public WechatOAuthServiceProvider(WechatConfig cfg) {
        config = cfg;
    }

    @Override
    public String getSlug() {
        return SLUG;
    }

    @Override
    public String getName() {
        return "微信登录";
    }


    @Override
    public Object notify(Map<String, Object> params, byte[] body) throws RestletException {
        log.debug("notify:> {} / {}", params, body != null ? body.length : 0);
        Assert.notEmpty(params, RestletException.badRequest("invalid request"));
        String signature = params.getOrDefault("signature", "").toString();
        Assert.notEmpty(signature, RestletException.badRequest("signature can not be empty"));
        String timestamp = params.getOrDefault("timestamp", "").toString();
        Assert.notEmpty(timestamp, RestletException.badRequest("timestamp can not be empty"));
        String nonce = params.getOrDefault("nonce", "").toString();
        Assert.notEmpty(nonce, RestletException.badRequest("nonce can not be empty"));
        String echostr = params.getOrDefault("echostr", "").toString();
        Assert.notEmpty(nonce, RestletException.badRequest("echostr can not be empty"));
        String openid = params.getOrDefault("openid", "").toString();
        String encryptType = params.getOrDefault("encrypt_type", "").toString();
        String msgSignature = params.getOrDefault("msg_signature", "").toString();
        log.debug("notify:> token = {}", config.getToken());
        log.debug("notify:> timestamp = {}", timestamp);
        log.debug("notify:> nonce = {}", nonce);
        log.debug("notify:> signature = {}", signature);
        log.debug("notify:> echostr = {}", echostr);
        log.debug("notify:> openid = {}", openid);
        log.debug("notify:> encrypt_type = {}", encryptType);
        log.debug("notify:> msg_signature = {}", msgSignature);
        log.debug("notify:> body = {} ", body == null ? "" : new String(body));

        List<String> ls = Arrays.asList(config.getToken(), timestamp, nonce);
        ls.sort(String::compareTo);
        String s = QuickHash.sha1().hash(String.join("", ls)).hex();
        log.debug("verify:> calculated signature: {}", s);
        if (!s.equals(signature)) {
            throw RestletException.badRequest("invalid signature");
        }
        return echostr;
    }

    @Override
    public String getCodeUrl(String state, String redirectUri) throws RestletException {
        Assert.notEmpty(config.getAppId(), RestletException.internalServerError("wechat appId can not be empty"));
        Assert.notEmpty(config.getAppSecret(), RestletException.internalServerError("wechat appSecret can not be empty"));
        Assert.notEmpty(config.getEndpoint(), RestletException.internalServerError("wechat endpoint can not be empty"));
        Assert.notEmpty(config.getScope(), RestletException.internalServerError("wechat scope can not be empty"));
        Assert.notEmpty(config.getResponseType(), RestletException.internalServerError("wechat responseType can not be empty"));
        String s = null;
        try {
            s = config.getEndpoint() +
                    "?appid=" + config.getAppId() +
                    "&response_type=" + config.getResponseType() +
                    "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
                    "&state=" + state +
                    "&scope=" + config.getScope() + "#wechat_redirect";
        } catch (UnsupportedEncodingException e) {
            throw RestletException.internalServerError("url encode failed");
        }
        return s;
    }

    /**
     * {
     * "access_token":"ACCESS_TOKEN",
     * "expires_in":7200,
     * "refresh_token":"REFRESH_TOKEN",
     * "openid":"OPENID",
     * "scope":"SCOPE",
     * "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
     * }
     *
     * @param code code returned by provider
     * @return
     * @throws RestletException
     */
    @Override
    public Map<String, Object> getAccessToken(String code) throws RestletException {
        Map<String, Object> result;
        String accessTokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + config.getAppId() + "&secret="
                + config.getAppSecret() + "&code=" + code + "&grant_type=" + config.getGrantType();
        HttpResponse resp = HttpRequest.get(accessTokenUrl).execute();
        if (resp.getStatus() != HttpStatus.HTTP_OK) {
            throw RestletException.serviceUnavailable("request to wechat failed");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            result = objectMapper.readValue(resp.body(), new TypeReference<Map<String, Object>>() {
            });
            log.debug("getAccessToken:> accessToken: {}", result);
        } catch (JsonProcessingException e) {
            throw RestletException.serviceUnavailable("request to wechat failed: " + e.getMessage());
        }
        Assert.notEmpty(result, RestletException.serviceUnavailable("request to wechat failed: invalid response"));
        String accessToken = result.getOrDefault("access_token", "").toString();
        Assert.notEmpty(accessToken, RestletException.serviceUnavailable("request to wechat failed: not included access_token"));
        String refreshToken = result.getOrDefault("refresh_token", "").toString();
        Assert.notEmpty(refreshToken, RestletException.serviceUnavailable("request to wechat failed: not included refresh_token"));
        String openid = result.getOrDefault("openid", "").toString();
        Assert.notEmpty(openid, RestletException.serviceUnavailable("request to wechat failed: not included openid"));
        String unionid = result.getOrDefault("unionid", "").toString();
//        if (unionid != null && !unionid.isEmpty()) {
        Map<String, Object> userInfo = getUserInfo(accessToken, openid);
        if (null != userInfo && !userInfo.isEmpty()) {
            log.debug("getAccessToken:> userInfo: {}", userInfo);
            result.putAll(userInfo);
        }
//        }
        return result;
    }


    /**
     * {
     * "openid":"OPENID",
     * "nickname":"NICKNAME",
     * "sex":1,
     * "province":"PROVINCE",
     * "city":"CITY",
     * "country":"COUNTRY",
     * "headimgurl": "https://thirdwx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0",
     * "privilege":[
     * "PRIVILEGE1",
     * "PRIVILEGE2"
     * ],
     * "unionid": " o6_bmasdasdsad6_2sgVt7hMZOPfL"
     * <p>
     * }
     *
     * @param accessToken
     * @param openid
     * @return
     */
    public Map<String, Object> getUserInfo(String accessToken, String openid) {
        Map<String, Object> result;
        String accessUrl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + accessToken + "&openid=" + openid;
        HttpResponse resp = HttpRequest.get(accessUrl).execute();
        if (resp.getStatus() != HttpStatus.HTTP_OK) {
            return null;
        }
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            result = objectMapper.readValue(resp.body(), new TypeReference<Map<String, Object>>() {
            });
        } catch (JsonProcessingException e) {
            return null;
        }
        return result;
    }
}
