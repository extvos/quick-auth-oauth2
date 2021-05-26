package org.extvos.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author shenmc
 */
@Service
public class ProviderServiceImpl implements ProviderService {

    @Autowired
    private OAuthProvider[] providers;

    @Override
    public OAuthProvider getProvider(String slug) {
        if(providers!=null){
            for(OAuthProvider p: providers){
                if(slug.equals(p.getSlug())){
                    return p;
                }
            }
        }
        return null;
    }

    @Override
    public OAuthProvider[] allProviders() {
        return providers;
    }
}
