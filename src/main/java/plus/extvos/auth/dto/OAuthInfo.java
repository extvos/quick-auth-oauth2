package plus.extvos.auth.dto;

import java.io.Serializable;
import java.util.Map;

/**
 * Open Account info when user try to login via OAuth
 *
 * @author shenmc
 */
public class OAuthInfo implements Serializable {
    private Serializable id;
    private Serializable userId;
    private String provider;
    private String openId;

    private String unionId;
    private Map<String, Object> extraInfo;

    public OAuthInfo() {

    }

    public OAuthInfo(Serializable userId, String provider, String openId, String unionId) {
        this.userId = userId;
        this.provider = provider;
        this.openId = openId;
        this.unionId = unionId;
    }

    public OAuthInfo(Serializable id, Serializable userId, String provider, String openId, String unionId) {
        this.id = id;
        this.userId = userId;
        this.provider = provider;
        this.openId = openId;
        this.unionId = unionId;
    }

    public OAuthInfo(Serializable id, Serializable userId, String provider, String openId, String unionId, Map<String, Object> extraInfo) {
        this.id = id;
        this.userId = userId;
        this.provider = provider;
        this.openId = openId;
        this.unionId = unionId;
        this.extraInfo = extraInfo;
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

    public String getUnionId() {
        return unionId;
    }

    public void setUnionId(String unionId) {
        this.unionId = unionId;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }

    public void setExtraInfo(Map<String, Object> extraInfo) {
        this.extraInfo = extraInfo;
    }

    public UserInfo buildUserInfo(String username, String password, String cellphone, String email) {
        UserInfo ui = new UserInfo(userId, username, password, cellphone, email, extraInfo);
        ui.setProvider(provider);
        ui.setOpenId(openId);
        ui.setUnionId(unionId);
        return ui;
    }

    @Override
    public String toString() {
        return "OAuthInfo{" +
                "id=" + id +
                ", userId=" + userId +
                ", provider='" + provider + '\'' +
                ", openId='" + openId + '\'' +
                ", unionId='" + unionId + '\'' +
                ", extraInfo=" + extraInfo +
                '}';
    }
}
