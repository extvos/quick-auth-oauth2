package org.extvos.auth.config;

import org.extvos.auth.service.StateService;
import org.extvos.auth.service.StateServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

/**
 * @author Mingcai SHEN
 */
@ComponentScan("org.extvos.auth")
public class AuthOAuth2AutoConfigure {
    @Bean
    @ConditionalOnMissingBean(StateService.class)
    StateService stateService() {
        return new StateServiceImpl();
    }
}
