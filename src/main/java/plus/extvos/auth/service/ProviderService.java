package plus.extvos.auth.service;

/**
 * @author Mingcai SHEN
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
