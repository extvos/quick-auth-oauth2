package org.extvos.auth.service;

import org.extvos.auth.entity.OAuthState;
import org.extvos.restlet.exception.RestletException;

/**
 * @author shenmc
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
