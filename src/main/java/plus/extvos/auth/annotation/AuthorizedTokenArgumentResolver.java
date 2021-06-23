package plus.extvos.auth.annotation;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import plus.extvos.auth.service.QuickAuthService;
import plus.extvos.auth.service.StateService;
import plus.extvos.restlet.exception.RestletException;
import plus.extvos.restlet.utils.SpringContextHolder;

/**
 * {@link AuthorizedToken} 注解的解析
 *
 * @author Mingcai SHEN
 */
public class AuthorizedTokenArgumentResolver implements HandlerMethodArgumentResolver {

    private StateService stateService;

    private StateService getStateService() {
        if (stateService == null) {
            stateService = SpringContextHolder.getBean(StateService.class);
        }
        return stateService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SessionUser.class);
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        if (null == subject) {
            return null;
        }
        if (supportsParameter(parameter) && subject.isAuthenticated()) {
            if (parameter.getParameterType().equals(String.class)) {
                return subject.getPrincipal();
            }
        }
        return subject.getPrincipal();
    }
}
