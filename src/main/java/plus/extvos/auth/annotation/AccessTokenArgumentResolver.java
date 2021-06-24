package plus.extvos.auth.annotation;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import plus.extvos.auth.dto.UserInfo;

/**
 * {@link AccessToken} 注解的解析
 *
 * @author Mingcai SHEN
 */
public class AccessTokenArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AccessToken.class);
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
            Session session = subject.getSession();
            if (parameter.getParameterType().equals(String.class)) {
                UserInfo ui = (UserInfo) session.getAttribute(UserInfo.USER_INFO_KEY);
                if(null != ui){
                    return ui.getOpenId();
                }
                return null;
            }
        }
        return null;
    }
}
