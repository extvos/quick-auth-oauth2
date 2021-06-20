package org.extvos.auth.service;

import org.extvos.auth.entity.OAuthState;
import org.extvos.restlet.exception.RestletException;

import java.util.Map;

/**
 * @author Mingcai SHEN
 */
public interface OAuthProvider {

    /**
     * The following constants are for raw map conversion, provider processed extra map info should convert the keys.
     */
    String NICK_NAME_KEY = "nickname";
    String AVATAR_URL_KEY = "avatarUrl";
    String OPEN_ID_KEY = "openid";
    String UNION_ID_KEY = "unionid";
    String SESSION_KEY = "session_key";
    String LANGUAGE_KEY = "language";
    String COUNTRY_KEY = "country";
    String COUNTRY_CODE_KEY = "countryCode";
    String PROVINCE_KEY = "province";
    String CITY_KEY = "city";
    String GENDER_KEY = "gender";
    String PHONE_NUMBER_KEY = "phoneNumber";


    /**
     * A unique identifier for service provider
     *
     * @return string of slug
     */
    String getSlug();

    /**
     * get provider name
     *
     * @return name as String
     */
    String getName();

    /**
     * get if provider support in page redirect.
     *
     * @return true if supported
     */
    default boolean redirectSupported() {
        return false;
    }

    ;

    /**
     * provider notification
     *
     * @param params params from request
     * @param body   request body from request
     * @return result
     * @throws RestletException if errors
     */
    Object notify(Map<String, Object> params, byte[] body) throws RestletException;

    /**
     * get code url for generate QrCode or redirect user browser
     *
     * @param state       a string to identify state of code url
     * @param redirectUri a string to give the redirectUri
     * @return a string of url.
     * @throws RestletException if errors
     */
    String getCodeUrl(String state, String redirectUri) throws RestletException;


//    /**
//     * Get access token info via code
//     *
//     * @param code code returned by provider
//     * @return map with results.
//     * @throws RestletException when errors
//     */
//    ProviderTokenResult getAccessToken(String code) throws RestletException;
//
//    /**
//     * get Session key by code
//     *
//     * @param code code returned by provider
//     * @return map with results
//     * @throws RestletException when errors
//     */
//    ProviderSessionResult getSessionKey(String code) throws RestletException;
//
//    /**
//     * Decrypt raw data with sessionKey
//     *
//     * @param sessionKey key
//     * @param raw        raw data
//     * @param iv         initial vector
//     * @param signature  signature
//     * @return map of data
//     * @throws RestletException when errors
//     */
//    Map<String, Object> decryptViaSessionKey(String sessionKey, String raw, String iv, String signature) throws RestletException;


    /**
     * run authorization with given code
     *
     * @param code      authorized code from provider
     * @param state     session state identity
     * @param via       parameter
     * @param authState previous state if already exists
     * @return updated authState or new
     * @throws RestletException when error
     */
    OAuthState authorized(String code, String state, String via, OAuthState authState) throws RestletException;

    /**
     * authorization updates for special situation
     *
     * @param params    mapped params
     * @param authState previous state if already exists
     * @return updated authState or new
     * @throws RestletException RestletException when error
     */
    OAuthState authorizeUpdate(Map<String, Object> params, OAuthState authState) throws RestletException;
}
