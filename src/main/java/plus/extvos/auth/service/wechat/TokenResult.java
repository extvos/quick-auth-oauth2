package plus.extvos.auth.service.wechat;

import java.util.Map;

class TokenResult {
    String openId;
    String unionId;
    String accessToken;
    String refreshToken;
    Integer expiresIn;
    Map<String, Object> extraInfo;


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
