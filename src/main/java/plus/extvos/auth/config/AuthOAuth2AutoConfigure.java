package plus.extvos.auth.config;

import plus.extvos.auth.service.StateService;
import plus.extvos.auth.service.StateServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author Mingcai SHEN
 */
@ComponentScan("plus.extvos.auth")
public class AuthOAuth2AutoConfigure {
    @Bean
    @ConditionalOnMissingBean(StateService.class)
    StateService stateService() {
        return new StateServiceImpl();
    }
}
