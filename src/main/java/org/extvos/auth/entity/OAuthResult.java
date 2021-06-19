package org.extvos.auth.entity;

import java.io.Serializable;
import java.util.Map;

/**
 * @author shenmc
 */
public class OAuthResult {
    private Serializable id;
    private String session;
    private String username;
    private String openId;
    private Map<String, Object> extraInfo;

    /**
     * {@link OAuthState }
     */
    private int status;

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getOpenId() {
        return openId;
    }

    public void setOpenId(String openId) {
        this.openId = openId;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public Serializable getId() {
        return id;
    }

    public void setId(Serializable id) {
        this.id = id;
    }

    public OAuthResult(Serializable id, String session, String username, String openId, int status) {
        this.id = id;
        this.session = session;
        this.username = username;
        this.openId = openId;
        this.status = status;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }
}
