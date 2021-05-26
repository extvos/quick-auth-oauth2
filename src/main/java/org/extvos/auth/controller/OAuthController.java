package org.extvos.auth.controller;

import org.extvos.auth.config.QuickAuthConfig;
import org.extvos.auth.dto.UserInfo;
import org.extvos.auth.entity.OAuthResult;
import org.extvos.auth.entity.OAuthState;
import org.extvos.auth.enums.AuthCode;
import org.extvos.auth.service.*;
import org.extvos.auth.shiro.QuickToken;
import org.extvos.common.utils.QrCode;
import org.extvos.restlet.RestletCode;
import org.extvos.restlet.Result;
import org.extvos.restlet.exception.RestletException;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

/**
 * OAuth2
 * Procedure 1:
 * ( Browser    ) QrCode  ----------------> Check Status ---------------------------------------->        Login
 * ( Mobile App )         |-> Access URL -> Redirect to OAuth2 Login URL -> Authorized URI -> Login Process -^
 * Procedure 2:
 * ( Browser    ) URL -> Access URL -> Redirect to OAuth2 Login URL -> Authorized URI -> Login Process -> Login
 *
 * @author shenmc
 */
@Api(tags = {"用户认证"})
@RestController
@RequestMapping("/auth/oauth2")
public class OAuthController {
    private static final Logger log = LoggerFactory.getLogger(OAuthController.class);

    @Autowired
    private QuickAuthConfig quickAuthConfig;

    @Autowired
    private QuickAuthService quickAuthService;

    @Autowired
    private OpenIdResolver openidResolver;

    @Autowired
    private ProviderService providerService;

    @Autowired
    private StateService stateService;

    @Value("${quick.auth.base-url:http://localhost}")
    private String baseUrl;

    @Value("${quick.auth.base.auto-register:false}")
    private boolean autoRegister;

    private OAuthProvider getProvider(String provider) throws RestletException {
        if (provider == null || provider.isEmpty()) {
            throw RestletException.badRequest("provider slug can not be empty");
        }
        OAuthProvider oAuthProvider = providerService.getProvider(provider);
        if (null == oAuthProvider) {
            throw RestletException.notFound("no provider named as '" + provider + "'");
        }
        return oAuthProvider;
    }

    private String getProviderLoginUri(OAuthProvider oAuthProvider, String redirectUri, String state) throws RestletException {
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = baseUrl;
            String prefix = System.getProperty("server.servlet.context-path");
            if (prefix != null && !prefix.isEmpty()) {
                redirectUri += prefix + "/auth/oauth2/" + oAuthProvider.getSlug() + "/authorized";
            } else {
                redirectUri += "/auth/oauth2/" + oAuthProvider.getSlug() + "/authorized";
            }
        }
        String s = oAuthProvider.getCodeUrl(state, redirectUri);
        log.debug("getProviderLoginUri:> {} {} {}", oAuthProvider.getSlug(), state, s);
        return s;
    }

    private String buildLoginUrl(OAuthProvider oAuthProvider, String redirectUri) throws RestletException {
        String gotoUrl = baseUrl;
        String prefix = System.getProperty("server.servlet.context-path");
        if (prefix != null && !prefix.isEmpty()) {
            gotoUrl += prefix + "/auth/oauth2/" + oAuthProvider.getSlug() + "/login-redirect";
        } else {
            gotoUrl += "/auth/oauth2/" + oAuthProvider.getSlug() + "/login-redirect";
        }
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession(true);
        OAuthState stateObj = new OAuthState(session.getId().toString());
        if (subject.isAuthenticated()) {
            stateObj.setUserInfo(quickAuthService.getUserByName(subject.getPrincipal().toString(), false));
        }
        stateObj.setStatus(0);
        stateService.put(stateObj.getSessionId(), stateObj);
        gotoUrl += "?state=" + stateObj.getSessionId();
        try {
            if (redirectUri != null && !redirectUri.isEmpty()) {
                gotoUrl += "&redirectUri=" + URLEncoder.encode(redirectUri, "UTF-8");
            }
        } catch (UnsupportedEncodingException e) {
            throw RestletException.internalServerError(e.getMessage());
        }
        log.debug("buildLoginUrl:> {}", gotoUrl);
        return gotoUrl;
    }

    @ApiOperation(value = "第三方登录持列表")
    @GetMapping(value = "/providers")
    public Result<List<OAuthProvider>> getProviders() throws RestletException {
        List<OAuthProvider> m = new LinkedList<>(Arrays.asList(providerService.allProviders()));
        return Result.data(m).success();
    }

    @ApiOperation(value = "第三方通知")
    @RequestMapping(value = "/{provider}/notify")
    public Object goVerify(@PathVariable("provider") String provider,
                           @RequestParam(required = false) Map<String, Object> params,
                           @RequestBody(required = false) byte[] body) throws RestletException {
        log.debug("goVerify:> {} {}", provider, params);
        OAuthProvider oAuthProvider = getProvider(provider);
        return oAuthProvider.notify(params, body);
    }

    @ApiOperation(value = "跳转第三方登录URL")
    @GetMapping(value = "/{provider}/login-redirect")
    public Result<?> goRedirect(@PathVariable("provider") String provider,
                                @RequestParam(value = "failureUri", required = false) String failureUri,
                                @RequestParam(value = "redirectUri", required = false) String redirectUri,
                                @RequestParam(value = "state", required = false) String state,
                                HttpServletResponse response) throws RestletException {
        OAuthProvider oAuthProvider = getProvider(provider);
        Subject subject = SecurityUtils.getSubject();
        String gotoUri = failureUri;
        if (state == null || state.isEmpty()) {
            Session session = subject.getSession(true);
            state = session.getId().toString();
        }
        OAuthState stateObj = stateService.get(state);
        if (null == stateObj) {
            stateObj = new OAuthState(state);
            if (subject.isAuthenticated()) {
                stateObj.setUserInfo(quickAuthService.getUserByName(subject.getPrincipal().toString(), false));
            }
            log.debug("goRedirect:> create new state: {}", stateObj.getSessionId());
        } else {
            log.debug("goRedirect:> get state via StateService: {}", stateObj.getSessionId());
        }
        stateObj.setStatus(1);
        stateService.put(stateObj.getSessionId(), stateObj);
        gotoUri = getProviderLoginUri(oAuthProvider, redirectUri, state);
        try {
            log.debug("goRedirect:> Redirecting to: {}", gotoUri);
            response.sendRedirect(gotoUri);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @ApiOperation(value = "第三方登录跳转URL")
    @GetMapping(value = "/{provider}/code-url")
    public Result<String> getCodeUrl(@PathVariable("provider") String provider,
                                     @RequestParam(value = "redirectUri", required = false) String redirectUri) throws RestletException {
        OAuthProvider oAuthProvider = getProvider(provider);
        return Result.data(buildLoginUrl(oAuthProvider, redirectUri)).success();
    }

    @ApiOperation(value = "第三方登录跳转QRCODE", notes = "获取图片QRCODE，直接输出图片", position = 3)
    @RequestMapping(produces = MediaType.IMAGE_PNG_VALUE,
            value = "/{provider}/code-img", method = RequestMethod.GET)
    protected ModelAndView getCodeUrl(@PathVariable("provider") String provider,
                                      @RequestParam(value = "redirectUri", required = false) String redirectUri,
                                      @RequestParam(required = false) Integer size,
                                      HttpServletResponse response) throws RestletException, IOException {
        OAuthProvider oAuthProvider = getProvider(provider);
        String url = buildLoginUrl(oAuthProvider, redirectUri);

        if (size == null || size < 64) {
            size = 256;
        }

        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/png");

        try {
            ServletOutputStream out = response.getOutputStream();
            QrCode.size(size).format("png").content(url).write(out);
            try {
                out.flush();
            } finally {
                out.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
            //LOG.error("WriterException occured", e);
        } //LOG.error("IOException occured", e);
        return null;
    }

    @ApiOperation(value = "第三方登录状态")
    @GetMapping(value = "/{provider}/auth-refresh")
    public Result<OAuthResult> getAuthorizedStatus(@PathVariable("provider") String provider) throws RestletException {
        OAuthState authState;
        Subject subject = SecurityUtils.getSubject();
        Session sess = subject.getSession();
        if (subject.isAuthenticated()) {
            UserInfo u = quickAuthService.getUserByName(subject.getPrincipal().toString(), true);
            authState = new OAuthState(sess.getId().toString());
            authState.setStatus(2);
            authState.setUserInfo(u);

        } else {
            authState = stateService.get(sess.getId().toString());
            if (null == authState) {
                throw RestletException.notFound("state not exists");
            }
            if (authState.getStatus() >= 3 && authState.getStatus() < 5) {
                UserInfo userInfo = authState.getUserInfo();
                if (userInfo != null) {
                    QuickToken tk = new QuickToken(userInfo.getUsername(), userInfo.getPassword(), "", "");
                    try {
                        subject.login(tk);
                        authState.setStatus(5);
                        stateService.put(sess.getId().toString(), authState);
                    } catch (Exception e) {
                        log.error("getAuthorizedStatus:> try to login failed by {} ", userInfo.getUsername(), e);
                        tk.clear();
                        throw RestletException.conflict("try to login failed");
                    }
                }
            }
        }
        if (authState.getUserInfo() != null) {
            authState.getUserInfo().setPassword("");
        }
        return Result.data(authState.asResult()).success();
    }


    @ApiOperation(value = "第三方登录回调")
    @GetMapping(value = "/{provider}/authorized")
    public Result<OAuthResult> authorized(@PathVariable("provider") String provider,
                                          @RequestParam("code") String code, @RequestParam("state") String state) throws RestletException {
        log.debug("authorized:> code={},state={}", code, state);
        Subject subject = SecurityUtils.getSubject();
        OAuthProvider oAuthProvider = getProvider(provider);
        if (state == null || state.isEmpty()) {
            throw RestletException.badRequest("state required");
        }
        OAuthState authState = stateService.get(state);
        if (null == authState || authState.getSessionId() == null || authState.getSessionId().isEmpty()) {
            throw RestletException.conflict("state of '" + state + "' not exists");
        }
        if (null == code || code.isEmpty()) {
            /* auth failed */
            authState.setStatus(-1);
            stateService.put(authState.getSessionId(), authState);
            throw RestletException.forbidden("authorization not accepted");
        }
        authState.setStatus(2);
        stateService.put(authState.getSessionId(), authState);
        String currentUsername = null;
        Serializable currentUserId = null;
        if (authState.getUserInfo() != null) {
            currentUsername = authState.getUserInfo().getUsername();
            currentUserId = authState.getUserInfo().getId();
        }
        Map<String, Object> extraInfo = oAuthProvider.getAccessToken(code);
        String openid = extraInfo.getOrDefault("openid", "").toString();
        UserInfo userInfo = openidResolver.resolve(provider, openid, currentUserId, extraInfo);
        if (null == userInfo) {
            if (!autoRegister) {
                throw RestletException.unauthorized("openid '" + openid + "' not link to any user,please register first");
            }
            userInfo = openidResolver.register(provider, openid, currentUsername, extraInfo);
            if (null == userInfo) {
                throw RestletException.forbidden("auto register openid '" + openid + "' failed.");
            }
        } else {
            openidResolver.update(provider, openid, extraInfo);
        }
        authState.setUserInfo(userInfo);
        authState.setOpenId(openid);
        authState.setExtraInfo(extraInfo);
        authState.setStatus(3);
        stateService.put(authState.getSessionId(), authState);
        // Do the login if state in current session.
        if (authState.getSessionId().equals(subject.getSession().getId().toString())) {
            QuickToken tk = new QuickToken(userInfo.getUsername(), userInfo.getPassword(), "", "");
            try {
                subject.login(tk);
                authState.setStatus(5);
                stateService.put(authState.getSessionId(), authState);
                return Result.data(authState.asResult()).success();
            } catch (Exception e) {
                log.error("getAuthorizedStatus:> try to login failed by {} ", userInfo.getUsername(), e);
                tk.clear();
                throw RestletException.conflict("try to login failed");
            }
        }
        return Result.data(authState.asResult()).success();
    }
}
