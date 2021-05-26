package org.extvos.auth.entity;

/**
 * @author shenmc
 */
public class OAuthResult {
    private String session;
    private String username;
    private String openId;

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

    public OAuthResult(String session, String username, String openId, int status) {
        this.session = session;
        this.username = username;
        this.openId = openId;
        this.status = status;
    }
}
