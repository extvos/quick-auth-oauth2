package plus.extvos.auth.dto;

import java.io.Serializable;
import java.util.Map;

/**
 * @author Mingcai SHEN
 */
public class OAuthState implements Serializable {

    /**
     * Status of current session
     * -1: failed
     * 0: initialized, nothing else was done
     * 1: oauth redirect(or QR-Code scanned and accessed)
     * 2: authorized accepted, waiting for openid.
     * 3: access token acquired, openid presented.
     * 4: user info acquired
     * 5: login finished
     */
    public static final int FAILED = -1;
    public static final int INITIALIZED = 0;
    public static final int REDIRECTED = 1;
    public static final int ACCEPTED = 2;
    public static final int ID_PRESENTED = 3;
    public static final int INFO_PRESENTED = 4;
    public static final int LOGGED_IN = 5;

    private String sessionId;

    private int status;

    private OAuthInfo authInfo;

    private UserInfo userInfo;

    private String redirectUri;

    private String failureUri;

    private String openId;

    private String token;

    private String refreshToken;

    private String sessionKey;

    private Map<String, Object> extraInfo;

    private String error;

    public OAuthState(String sessId) {
        sessionId = sessId;
    }

    public OAuthResult asResult() {
        OAuthResult ret = new OAuthResult(userInfo == null ? null : userInfo.getUserId(), sessionId, userInfo == null ? "" : userInfo.getUsername(), openId, status);
        if (extraInfo != null) {
            ret.setExtraInfo(extraInfo);
        }
        return ret;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(UserInfo userInfo) {
        this.userInfo = userInfo;
    }


    public OAuthInfo getAuthInfo() {
        return authInfo;
    }

    public void setAuthInfo(OAuthInfo authInfo) {
        this.authInfo = authInfo;
    }

    public String getOpenId() {
        return openId;
    }

    public void setOpenId(String openId) {
        this.openId = openId;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getFailureUri() {
        return failureUri;
    }

    public void setFailureUri(String failureUri) {
        this.failureUri = failureUri;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}
