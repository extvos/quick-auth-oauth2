package org.extvos.auth.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.extvos.auth.entity.OAuthState;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * @author shenmc
 */
public class StateServiceImpl implements StateService {

    private Cache<String, OAuthState> stateCache;

    public StateServiceImpl() {
        stateCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(5L))
                .maximumSize(1000L)
                .initialCapacity(100)
                .build();
    }

    @Override
    public OAuthState get(String state) {
        return stateCache.getIfPresent(state);
    }

    @Override
    public void put(String state, OAuthState obj) {
        stateCache.put(state, obj);
    }
}
