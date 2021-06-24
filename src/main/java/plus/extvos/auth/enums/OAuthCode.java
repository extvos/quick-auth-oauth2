package plus.extvos.auth.enums;

import plus.extvos.restlet.Code;

/**
 * @author Mingcai SHEN
 */

public enum OAuthCode implements Code {
    /**
     *
     */
    UNKNOWN_ERROR(50011, "Unknown Error");

    private final int value;
    private final String desc;

    OAuthCode(int v, String d) {
        value = v;
        desc = d;
    }


    @Override
    public int value() {
        return this.value;
    }

    @Override
    public int status() {
        return this.value / 100;
    }

    @Override
    public String desc() {
        return this.desc;
    }
}
