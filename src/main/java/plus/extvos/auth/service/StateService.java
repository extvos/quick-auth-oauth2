package plus.extvos.auth.service;

import plus.extvos.auth.dto.OAuthState;

/**
 * @author Mingcai SHEN
 */
public interface StateService {
    /**
     * Get state by id;
     *
     * @param state id
     * @return state object
     */
    OAuthState get(String state);

    /**
     * Set state of name
     *
     * @param state id
     * @param obj   state object
     */
    void put(String state, OAuthState obj);
}
