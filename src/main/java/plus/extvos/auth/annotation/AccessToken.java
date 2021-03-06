package plus.extvos.auth.annotation;

import java.lang.annotation.*;

/**
 * 获取当前用户的第三方访问Token
 *
 * @author Mingcai SHEN
 * @see AccessTokenArgumentResolver
 */
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AccessToken {
}
