package org.extvos.auth.service;

/**
 * @author shenmc
 */
public interface ProviderService {
    /**
     * Get a provider by slug
     * @param slug unique name
     * @return provider or null
     */
    OAuthProvider getProvider(String slug);

    /**
     * get all providers
     * @return array of providers
     */
    OAuthProvider[] allProviders();
}
