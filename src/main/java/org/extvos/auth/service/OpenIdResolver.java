package org.extvos.auth.service;

import org.extvos.auth.dto.UserInfo;
import org.extvos.restlet.exception.RestletException;

import java.io.Serializable;
import java.util.Map;

/**
 * @author shenmc
 */
public interface OpenIdResolver {
    /**
     * get UserInfo via openId
     *
     * @param provider provider name of openId
     * @param openId   from authenticator
     * @param userId   from if user specified
     * @param params   a map result from authenticator
     * @return userInfo or null
     * @throws RestletException on error
     */
    UserInfo resolve(String provider, String openId, Serializable userId, Map<String, Object> params) throws RestletException;

    /**
     * register a new user according to openId;
     *
     * @param provider provider name of openId
     * @param openId   from authenticator
     * @param username from if user specified
     * @param params   a map result from authenticator
     * @return userInfo or null
     * @throws RestletException on error
     */
    UserInfo register(String provider, String openId, String username, Map<String, Object> params) throws RestletException;

    /**
     * Update user openid information
     *
     * @param provider as string
     * @param openId   as string
     * @param params   parameters from provider.
     * @return true if updated.
     * @throws RestletException when error.
     */
    boolean update(String provider, String openId, Map<String, Object> params) throws RestletException;
}
