package plus.extvos.auth.service.wechat;

class SessionResult {
    String openId;
    String unionId;
    String sessionKey;

    public SessionResult(String openId, String unionId, String sessionKey) {
        this.openId = openId;
        this.unionId = unionId;
        this.sessionKey = sessionKey;
    }
}
