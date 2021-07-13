package plus.extvos.auth.service;

import plus.extvos.auth.dto.OAuthInfo;
import plus.extvos.common.exception.ResultException;

import java.io.Serializable;
import java.util.Map;

/**
 * @author Mingcai SHEN
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
     * @throws ResultException on error
     */
    OAuthInfo resolve(String provider, String openId, Serializable userId, Map<String, Object> params) throws ResultException;

    /**
     * register a new user according to openId;
     *
     * @param provider provider name of openId
     * @param openId   from authenticator
     * @param username from if user specified
     * @param password from if user specified
     * @param params   a map result from authenticator
     * @return userInfo or null
     * @throws ResultException on error
     */
    OAuthInfo register(String provider, String openId, String username, String password, Map<String, Object> params) throws ResultException;

    /**
     * Update user openid information
     *
     * @param provider as string
     * @param openId   as string
     * @param userId   as user Id
     * @param params   parameters from provider.
     * @return UserInfo of updated.
     * @throws ResultException when error.
     */
    OAuthInfo update(String provider, String openId, Serializable userId, Map<String, Object> params) throws ResultException;
}
