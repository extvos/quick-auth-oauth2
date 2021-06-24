package plus.extvos.auth.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import plus.extvos.auth.dto.OAuthState;

import java.time.Duration;

/**
 * @author Mingcai SHEN
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
