package org.extvos.auth.service;

import org.extvos.restlet.exception.RestletException;

import java.util.Map;

/**
 * @author shenmc
 */
public interface OAuthProvider {

    /**
     * A unique identifier for service provider
     *
     * @return string of slug
     */
    String getSlug();

    /**
     * get provider name
     * @return name as String
     */
    String getName();

    /**
     * get if provider support in page redirect.
     * @return true if supported
     */
    default boolean redirectSupported(){ return false; };

    /**
     * provider notification
     * @param params params from request
     * @param body request body from request
     * @return result
     * @throws RestletException if errors
     */
    Object notify(Map<String,Object> params, byte[] body) throws RestletException;

    /**
     * get code url for generate QrCode or redirect user browser
     *
     * @param state a string to identify state of code url
     * @param redirectUri a string to give the redirectUri
     * @return a string of url.
     * @throws RestletException if errors
     */
    String getCodeUrl(String state,String redirectUri) throws RestletException;


    /**
     * Get access token info via code
     * @param code code returned by provider
     * @return map with results.
     * @throws RestletException when errors
     */
    Map<String,Object> getAccessToken(String code) throws RestletException;
}
