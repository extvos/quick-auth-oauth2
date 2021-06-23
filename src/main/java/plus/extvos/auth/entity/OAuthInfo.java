package plus.extvos.auth.entity;

import java.io.Serializable;
import java.util.Map;

/**
 * @author shenmc
 */
public class OAuthInfo {
    private Serializable id;
    private Serializable userId;
    private String provider;
    private String openId;
    private Map<String, Object> extraInfo;

    public OAuthInfo(){

    }

    public OAuthInfo(Serializable userId, String provider, String openId) {
        this.userId = userId;
        this.provider = provider;
        this.openId = openId;
    }

    public OAuthInfo(Serializable id, Serializable userId, String provider, String openId) {
        this.id = id;
        this.userId = userId;
        this.provider = provider;
        this.openId = openId;
    }

    public Serializable getId() {
        return id;
    }

    public void setId(Serializable id) {
        this.id = id;
    }

    public Serializable getUserId() {
        return userId;
    }

    public void setUserId(Serializable userId) {
        this.userId = userId;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
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
}
