package org.extvos.auth.entity;

import org.extvos.auth.dto.UserInfo;

import java.io.Serializable;
import java.util.Map;

/**
 * @author shenmc
 */
public class OAuthState implements Serializable {

    private String sessionId;

    /**
     * Status of current session
     * -1: failed
     * 0: initialized, nothing else was done
     * 1: oauth redirect(or QR-Code scanned and accessed)
     * 2: authorized accepted
     * 3: access token acquired
     * 4: extra info acquired
     * 5: login finished
     */
    private int status;

    private UserInfo userInfo;

    private String redirectUri;

    private String failureUri;

    private String openId;

    private Map<String, Object> extraInfo;

    public OAuthState(String sessId) {
        sessionId = sessId;
    }

    public OAuthResult asResult() {
        return new OAuthResult(sessionId, userInfo == null ? "" : userInfo.getUsername(), openId, status);
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
}
