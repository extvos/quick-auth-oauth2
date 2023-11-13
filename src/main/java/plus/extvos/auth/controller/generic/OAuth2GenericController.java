package plus.extvos.auth.controller.generic;

import io.swagger.annotations.Api;
import org.springframework.web.bind.annotation.*;
import plus.extvos.auth.dto.OAuthResult;
import plus.extvos.common.Result;
import plus.extvos.common.exception.ResultException;

import javax.servlet.http.HttpServletResponse;

@Api(tags = {"OAuth2认证"})
//@RestController
@RequestMapping("/auth/oauth2/{provider}")
public class OAuth2GenericController {
    @GetMapping(value = "/authorized")
    public Result<OAuthResult> authorized(@PathVariable("provider") String provider,
                                          @RequestParam(value = "code") String code,
                                          @RequestParam(value = "state", required = false) String state,
                                          HttpServletResponse response) throws ResultException {
        throw ResultException.notImplemented();
    }
}
