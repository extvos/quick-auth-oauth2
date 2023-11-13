package plus.extvos.auth.service.generic;

import plus.extvos.auth.dto.OAuth2Config;

import java.util.List;

public interface OAuth2ConfigService {
    List<OAuth2Config> getAllConfig();
    OAuth2Config getConfig(String name);
}
