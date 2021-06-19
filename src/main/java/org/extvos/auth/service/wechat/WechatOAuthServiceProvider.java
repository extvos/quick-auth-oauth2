package org.extvos.auth.service.wechat;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpStatus;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.extvos.auth.entity.OAuthState;
import org.extvos.auth.service.OAuthProvider;
import org.extvos.common.utils.QuickHash;
import org.extvos.restlet.Assert;
import org.extvos.restlet.exception.RestletException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.AlgorithmParameters;
import java.security.Security;
import java.util.*;

/**
 * @author shenmc
 */
@Service
public class WechatOAuthServiceProvider implements OAuthProvider {

    private static final Logger log = LoggerFactory.getLogger(WechatOAuthServiceProvider.class);
    public static final String SLUG = "wechat";

    private static final String SESSION_VIA = "SESSIONKEY";

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

    private static final String[] keyMap = new String[]{
            OAuthProvider.NICK_NAME_KEY + ":" + "nickname",
            OAuthProvider.NICK_NAME_KEY + ":" + "nickName",
            OAuthProvider.AVATAR_URL_KEY + ":" + "headimgurl",
            OAuthProvider.AVATAR_URL_KEY + ":" + "avatarUrl",
            OAuthProvider.OPEN_ID_KEY + ":" + "openid",
            OAuthProvider.UNION_ID_KEY + ":" + "unionid",
            OAuthProvider.SESSION_KEY + ":" + "session_key",
            OAuthProvider.LANGUAGE_KEY + ":" + "language",
            OAuthProvider.COUNTRY_KEY + ":" + "country",
            OAuthProvider.PROVINCE_KEY + ":" + "province",
            OAuthProvider.CITY_KEY + ":" + "city",
            OAuthProvider.GENDER_KEY + ":" + "gender",
            OAuthProvider.PHONE_NUMBER_KEY + ":" + "cellphone",
            OAuthProvider.PHONE_NUMBER_KEY + ":" + "phoneNumber",
            OAuthProvider.PHONE_NUMBER_KEY + ":" + "purePhoneNumber",
            OAuthProvider.COUNTRY_CODE_KEY + ":" + "countryCode",
    };

    static class SessionResult {
        String openId;
        String unionId;
        String sessionKey;

        public SessionResult(String openId, String unionId, String sessionKey) {
            this.openId = openId;
            this.unionId = unionId;
            this.sessionKey = sessionKey;
        }
    }

    static class TokenResult {
        private String openId;
        private String unionId;
        private String accessToken;
        private String refreshToken;
        private Integer expiresIn;
        private Map<String, Object> extraInfo;


        public TokenResult() {

        }

        public TokenResult(String openId, String unionId, String accessToken, String refreshToken, Integer expiresIn) {
            this.openId = openId;
            this.unionId = unionId;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.expiresIn = expiresIn;
        }
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
     * @return ProviderTokenResult
     * @throws RestletException if errors
     */
    public TokenResult getAccessToken(String code) throws RestletException {
        String accessTokenUrl = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" + config.getAppId() + "&secret="
                + config.getAppSecret() + "&code=" + code + "&grant_type=" + config.getGrantType();
        HttpResponse resp = HttpRequest.get(accessTokenUrl).execute();
        if (resp.getStatus() != HttpStatus.HTTP_OK) {
            throw RestletException.serviceUnavailable("request to wechat failed");
        }
        Map<String, Object> map;
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            map = objectMapper.readValue(resp.body(), new TypeReference<Map<String, Object>>() {
            });
            log.debug("getAccessToken:> accessToken: {}", map);
        } catch (JsonProcessingException e) {
            throw RestletException.serviceUnavailable("request to wechat failed: " + e.getMessage());
        }
        Assert.notEmpty(map, RestletException.serviceUnavailable("request to wechat failed: invalid response"));
        String accessToken = map.getOrDefault("access_token", "").toString();
        Assert.notEmpty(accessToken, RestletException.serviceUnavailable("request to wechat failed: not included access_token"));
        String refreshToken = map.getOrDefault("refresh_token", "").toString();
        Assert.notEmpty(refreshToken, RestletException.serviceUnavailable("request to wechat failed: not included refresh_token"));
        String openid = map.getOrDefault("openid", "").toString();
        Assert.notEmpty(openid, RestletException.serviceUnavailable("request to wechat failed: not included openid"));
        String unionid = map.getOrDefault("unionid", "").toString();
        int expires_in = (int) map.getOrDefault("expires_in", 0);
        TokenResult result = new TokenResult(
                openid, unionid, accessToken, refreshToken, expires_in);
        Map<String, Object> userInfo = getUserInfo(accessToken, openid);
        result.extraInfo = userInfo;
        if (null != userInfo && !userInfo.isEmpty()) {
            log.debug("getAccessToken:> userInfo: {}", userInfo);
            map.putAll(userInfo);
        }
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
    public Map<String, Object> getUserInfo(String accessToken, String openid) throws RestletException {
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> mm;
        String accessUrl = "https://api.weixin.qq.com/sns/userinfo?access_token=" + accessToken + "&openid=" + openid;
        HttpResponse resp = HttpRequest.get(accessUrl).execute();
        if (resp.getStatus() != HttpStatus.HTTP_OK) {
            return null;
        }
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            mm = objectMapper.readValue(resp.body(), new TypeReference<Map<String, Object>>() {
            });
        } catch (JsonProcessingException e) {
            return null;
        }
        for (String key : keyMap) {
            String[] ks = key.split(":");
            if (mm.containsKey(ks[1])) {
                Object o = mm.get(ks[1]);
                result.put(ks[0], o);
            }
        }
        return result;
    }

    /**
     * GET https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
     */
    public SessionResult getSessionKey(String code) throws RestletException {
        String getUrl = "https://api.weixin.qq.com/sns/jscode2session?";
        getUrl += "appid=" + config.getAppId();
        getUrl += "&secret=" + config.getAppSecret();
        getUrl += "&js_code=" + code;
        getUrl += "&grant_type=authorization_code";
        log.debug("getSessionKey:> {}", getUrl);
        HttpResponse resp = HttpRequest.get(getUrl).execute();
        if (resp.getStatus() != HttpStatus.HTTP_OK) {
            throw RestletException.serviceUnavailable("no response");
        }
        Map<String, Object> map;
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            map = objectMapper.readValue(resp.body(), new TypeReference<Map<String, Object>>() {
            });
        } catch (JsonProcessingException e) {
            throw RestletException.serviceUnavailable("request to wechat failed: " + e.getMessage());
        }
        Assert.notEmpty(map, RestletException.serviceUnavailable("request to wechat failed: invalid response"));
        if (map.containsKey("errcode") && !map.get("errcode").equals(0)) {
            throw RestletException.serviceUnavailable("request to wechat failed: invalid errcode " + map.get("errcode"));
        }
        String openId = map.getOrDefault("openid", "").toString();
        Assert.notEmpty(openId, RestletException.serviceUnavailable("request to wechat failed: not included openid"));
        String unionId = map.getOrDefault("unionid", "").toString();
//        Assert.notEmpty(unionId, RestletException.serviceUnavailable("request to wechat failed: not included unionid"));
        String sessionKey = map.getOrDefault("session_key", "").toString();
        Assert.notEmpty(sessionKey, RestletException.serviceUnavailable("request to wechat failed: not included session_key"));
        return new SessionResult(openId, unionId, sessionKey);

    }

    public Map<String, Object> decryptViaSessionKey(String sessionKey, String encryptedData, String iv, String signature) throws RestletException {
        log.debug("decryptViaSessionKey:> sessionKey={}", sessionKey);
        log.debug("decryptViaSessionKey:> iv={}", iv);
        log.debug("decryptViaSessionKey:> signature={}", signature);
//        Assert.notEmpty(signature, RestletException.badRequest("signature required"));
        Base64.Decoder decoder = Base64.getDecoder();
        // 被加密的数据
        byte[] dataByte = decoder.decode(encryptedData);
        // 加密秘钥
        byte[] keyByte = decoder.decode(sessionKey);
        // 偏移量
        byte[] ivByte = decoder.decode(iv);

        try {
            // 如果密钥不足16位，那么就补足.  这个if 中的内容很重要
            int base = 16;
            if (keyByte.length % base != 0) {
                int groups = keyByte.length / base + 1; //(keyByte.length % base != 0 ? 1 : 0);
                byte[] temp = new byte[groups * base];
                Arrays.fill(temp, (byte) 0);
                System.arraycopy(keyByte, 0, temp, 0, keyByte.length);
                keyByte = temp;
            }
            // 初始化
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            SecretKeySpec spec = new SecretKeySpec(keyByte, "AES");
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
            parameters.init(new IvParameterSpec(ivByte));
            // 初始化
            cipher.init(Cipher.DECRYPT_MODE, spec, parameters);
            byte[] resultByte = cipher.doFinal(dataByte);
            log.debug("decryptViaSessionKey:> {}", new String(resultByte));
            if (null != resultByte && resultByte.length > 0) {
                Map<String, Object> ret = new HashMap<>();
                ObjectMapper objectMapper = new ObjectMapper();
                try {
                    Map<String, Object> map = objectMapper.readValue(resultByte, new TypeReference<Map<String, Object>>() {
                    });
                    for (String key : keyMap) {
                        String[] ks = key.split(":");
                        if (map.containsKey(ks[1])) {
                            Object o = map.get(ks[1]);
                            ret.put(ks[0], o);
                        }
                    }
                    return ret;
                } catch (JsonProcessingException e) {
                    throw RestletException.serviceUnavailable("request to wechat failed: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw RestletException.badRequest(e.getMessage());
        }
        throw RestletException.badRequest("unknown error on decrypt data");
    }

/*
{
    "phoneNumber": "13580006666",
    "purePhoneNumber": "13580006666",
    "countryCode": "86",
    "watermark":
    {
        "appid":"APPID",
        "timestamp": TIMESTAMP
    }
}

{
    "openId": "OPENID",
    "nickName": "NICKNAME",
    "gender": GENDER,
    "city": "CITY",
    "province": "PROVINCE",
    "country": "COUNTRY",
    "avatarUrl": "AVATARURL",
    "unionId": "UNIONID",
    "watermark":
    {
        "appid":"APPID",
        "timestamp":TIMESTAMP
    }
}
*/


    @Override
    public OAuthState authorized(String code, String state, String via, OAuthState authState) throws RestletException {
        Assert.notEmpty(code, RestletException.badRequest("invalid code"));
        Assert.notNull(authState, RestletException.internalServerError("invalid authState"));
        if (SESSION_VIA.equals(via)) {
            SessionResult result = getSessionKey(code);
            authState.setOpenId(result.openId);
            authState.setSessionKey(result.sessionKey);
        } else {
            TokenResult result = getAccessToken(code);
            authState.setOpenId(result.openId);
        }
        authState.setStatus(OAuthState.ID_PRESENTED);
        return authState;
    }

    @Override
    public OAuthState authorizeUpdate(Map<String, Object> params, OAuthState authState) throws RestletException {
        Assert.notEmpty(params, RestletException.badRequest("invalid params"));
        Assert.notNull(authState, RestletException.internalServerError("invalid authState"));
        String raw = params.getOrDefault("raw", "").toString();
        Assert.notEmpty(raw, RestletException.badRequest("raw required"));
        String iv = params.getOrDefault("iv", "").toString();
        Assert.notEmpty(iv, RestletException.badRequest("iv required"));
        String signature = params.getOrDefault("signature", "").toString();
//        Assert.notEmpty(signature, RestletException.badRequest("signature required"));

        Map<String, Object> rawMap = decryptViaSessionKey(authState.getSessionKey(), raw, iv, signature);
        Assert.notEmpty(rawMap, RestletException.badRequest("invalid raw data"));
        if (authState.getExtraInfo() != null) {
            rawMap.putAll(authState.getExtraInfo());
        }
        authState.setExtraInfo(rawMap);
        return authState;
    }

}
