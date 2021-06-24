package plus.extvos.auth.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.auth.dto.OAuthInfo;
import plus.extvos.auth.dto.OAuthResult;
import plus.extvos.auth.dto.OAuthState;
import plus.extvos.auth.dto.UserInfo;
import plus.extvos.auth.service.*;
import plus.extvos.auth.shiro.QuickToken;
import plus.extvos.common.Validator;
import plus.extvos.common.utils.QrCode;
import plus.extvos.common.utils.QuickHash;
import plus.extvos.restlet.Assert;
import plus.extvos.restlet.Result;
import plus.extvos.restlet.exception.RestletException;

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
 * @author Mingcai SHEN
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
        stateObj.setStatus(OAuthState.INITIALIZED);
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
        stateObj.setStatus(OAuthState.REDIRECTED);
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
            authState.setStatus(OAuthState.LOGGED_IN);
            authState.setUserInfo(u);

        } else {
            authState = stateService.get(sess.getId().toString());
            if (null == authState) {
                throw RestletException.notFound("state not exists");
            }
            if (authState.getStatus() >= OAuthState.ID_PRESENTED && authState.getStatus() < OAuthState.LOGGED_IN) {
                UserInfo userInfo = authState.getUserInfo();
                if (userInfo != null) {
                    QuickToken tk = new QuickToken(userInfo.getUsername(), userInfo.getPassword(), "", "");
                    try {
                        subject.login(tk);
                        authState.setStatus(OAuthState.LOGGED_IN);
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


    @ApiOperation(value = "第三方登录回调", notes = "via should be 'SESSIONKEY' when calling via Session Key mode")
    @GetMapping(value = "/{provider}/authorized")
    public Result<OAuthResult> authorized(@PathVariable("provider") String provider,
                                          @RequestParam(value = "code") String code,
                                          @RequestParam(value = "state", required = false) String state,
                                          @RequestParam(value = "via", required = false) String via) throws RestletException {
        log.debug("authorized:> code={},state={}", code, state);
        Subject subject = SecurityUtils.getSubject();
        OAuthProvider oAuthProvider = getProvider(provider);
        if (Validator.isEmpty(code)) {
            throw RestletException.forbidden("authorization not accepted");
        }
        if (Validator.isEmpty(state)) {
            Session session = subject.getSession(true);
            state = session.getId().toString();
        }
        OAuthState authState = stateService.get(state);
        if (authState == null || Validator.isEmpty(authState.getSessionId())) {
            log.debug("authorized:> state of '{}' not exists, make a new one...", state);
            authState = new OAuthState(state);
        }
        try {
            authState = oAuthProvider.authorized(code, state, via, authState);
        } catch (RestletException e) {
            authState.setStatus(OAuthState.FAILED);
            authState.setError(e.getMessage());
            stateService.put(authState.getSessionId(), authState);
            throw e;
        }
        authState.setStatus(OAuthState.ACCEPTED);
        stateService.put(authState.getSessionId(), authState);
        String currentUsername = null;
        Serializable currentUserId = null;
        if (authState.getUserInfo() != null) {
            currentUsername = authState.getUserInfo().getUsername();
            currentUserId = authState.getUserInfo().getUserId();
        }
        Assert.notEmpty(authState.getOpenId(), RestletException.serviceUnavailable("openid not provided"));
        Map<String, Object> extraInfo = authState.getExtraInfo();
        String openId = authState.getOpenId();
        authState.setOpenId(openId);
        authState.setStatus(OAuthState.ID_PRESENTED);
        stateService.put(authState.getSessionId(), authState);
        OAuthInfo authInfo = openidResolver.resolve(provider, openId, currentUserId, extraInfo);
        if (null == authInfo) {
            if (!autoRegister) {
                log.debug("authorized:> authInfo of {} not resolved, auto register disabled.", openId);
                return Result.data(authState.asResult()).success();
            }
            if (Validator.notEmpty(extraInfo)) {
                authInfo = openidResolver.register(provider, openId, currentUsername, null, extraInfo);
                authState.setExtraInfo(authInfo.getExtraInfo());
            } else {
                return Result.data(authState.asResult()).success();
            }
//            if (null == authInfo) {
//                throw RestletException.forbidden("auto register openid '" + openId + "' failed.");
//            }
        } else if (Validator.notEmpty(extraInfo)) {
            log.debug("authorized:> userInfo of {} resolved as {}, try to update...", openId, authInfo.getUserId());
            authInfo = openidResolver.update(provider, openId, authInfo.getUserId(), extraInfo);
        }
        UserInfo userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
        userInfo.setProvider(provider);
        userInfo.setOpenId(authInfo.getOpenId());
        userInfo.setExtraInfo(authInfo.getExtraInfo());
        authState.setUserInfo(userInfo);
        authState.setAuthInfo(authInfo);
        authState.setStatus(OAuthState.INFO_PRESENTED);
        stateService.put(authState.getSessionId(), authState);
        if (quickAuthConfig.isPhoneRequired() && Validator.isEmpty(userInfo.getCellphone())) {
            log.debug("authorized:> use cellphone not presented ...");
            return Result.data(authState.asResult()).success();
        }
        // Do the login if state in current session.
        if (authState.getSessionId().equals(subject.getSession().getId().toString())) {
            log.debug("authorized:> trying to login account {} / {}  / {} ...", userInfo.getUsername(), authState.getOpenId(), userInfo.getPassword());
            QuickToken tk = new QuickToken(userInfo.getUsername(), userInfo.getPassword(), "", "");
            try {
                subject.login(tk);
                authState.setStatus(OAuthState.LOGGED_IN);
                authState.setExtraInfo(authInfo.getExtraInfo());
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

    @ApiOperation(value = "第三方会话更新", notes = "在第三方认证调用authorized接口没有完成登录时，通过更新数据完成注册登录流程，目前用于小程序认证登录")
    @PostMapping(value = "/{provider}/session-update")
    public Result<OAuthResult> authorizedUpdate(@PathVariable("provider") String provider,
                                                @RequestParam(required = false) Map<String, Object> params,
                                                @RequestBody(required = false) Map<String, Object> objectMap) throws RestletException {
        /*
        @RequestParam(value = "username", required = false) String username,
        @RequestParam(value = "password", required = false) String password,
        @RequestParam(value = "raw", required = false) String raw,
        @RequestParam(value = "iv", required = false) String iv,
        @RequestParam(value = "signature", required = false) String signature,
         */
        Map<String, Object> requestParams = new HashMap<>();
        if (Validator.notEmpty(params)) {
            requestParams.putAll(params);
        }
        if (Validator.notEmpty(objectMap)) {
            requestParams.putAll(objectMap);
        }
        log.debug("registerSession:> provider={}, params={}", provider, requestParams);
        Assert.notEmpty(requestParams, RestletException.badRequest("empty request"));
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        if (null == session) {
            throw RestletException.forbidden("not in a valid session.");
        }
        String state = session.getId().toString();
        OAuthProvider oAuthProvider = getProvider(provider);
        OAuthState authState = stateService.get(state);
        if (authState == null || Validator.isEmpty(authState.getSessionId())) {
            throw RestletException.conflict("Session state of '" + state + "' not exists");
        }
        log.debug("registerSession:> authState: {} / {}", authState, requestParams);
        Assert.greaterThan(authState.getStatus(), OAuthState.ACCEPTED, RestletException.forbidden("session not in state"));

//        Assert.notEmpty(authState.getSessionKey(), RestletException.forbidden("session key not presented"));
//        Assert.notEmpty(authState.getOpenId(), RestletException.forbidden("openid not presented"));
        String username, password;
        username = objectMap.getOrDefault("username", "").toString();
        password = objectMap.getOrDefault("password", "").toString();

        if (Validator.isEmpty(username)) {
            username = authState.getOpenId();
        }
        if (Validator.isEmpty(password)) {
            password = QuickHash.md5().hash(authState.getOpenId()).hex();
        }

        authState = oAuthProvider.authorizeUpdate(requestParams, authState);

//        Assert.notEmpty(rawMap, RestletException.badRequest("empty raw map"));
//        log.debug("registerSession:> rawMap = {}", rawMap);

        UserInfo userInfo = authState.getUserInfo();
        OAuthInfo authInfo = authState.getAuthInfo();
        Map<String, Object> extraInfo = authState.getExtraInfo();

        if (authState.getStatus() >= OAuthState.LOGGED_IN) {
            openidResolver.update(provider, authState.getOpenId(), authInfo == null ? null : authInfo.getUserId(), extraInfo);
            return Result.data(authState.asResult()).success();
        }
        // TODO: register user .... ???
        // Present status
        authState.setStatus(OAuthState.INFO_PRESENTED);
        stateService.put(authState.getSessionId(), authState);

        // get userInfo by openId if userInfo not presented
        if (null == authInfo) {
            authInfo = openidResolver.resolve(provider, authState.getOpenId(), null, extraInfo);
        }

        if (null == userInfo && null != authInfo) {
            userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
        }

        // get userInfo by phone number if userInfo not presented and phone is ready
        if (null == userInfo && Validator.notEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
            userInfo = quickAuthService.getUserByPhone(extraInfo.get(OAuthProvider.PHONE_NUMBER_KEY).toString(), false);
        }

        if (quickAuthConfig.isPhoneRequired()) {
            if (Validator.isEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
                // phone required
                log.debug("registerSession:> phone required, check phone number ...");
                return Result.data(authState.asResult()).success();
            }
        }

        // try to register user if userInfo not presented
        if (null == userInfo) {
            if (!autoRegister) {
                log.debug("registerSession:> not allow to auto register, return status 403");
                throw RestletException.forbidden("not allowed to login");
//                return Result.data(authState.asResult()).success();
            } else {
                log.debug("registerSession:> auto register user ...");
                authInfo = openidResolver.register(provider, authState.getOpenId(), username, password, extraInfo);
                userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
            }
        } else {
            log.debug("registerSession:> resolved used: {}, update ...", userInfo.getUsername());
            authInfo = openidResolver.update(provider, authState.getOpenId(), userInfo.getUserId(), extraInfo);
        }
        if (authInfo != null && authInfo.getExtraInfo() != null) {
            extraInfo.putAll(authInfo.getExtraInfo());
        }
        authState.setUserInfo(userInfo);
        authState.setAuthInfo(authInfo);
        authState.setExtraInfo(extraInfo);

        // trying to login
        log.debug("registerSession:> try to logging user '{}' ... ", userInfo.getUsername());
        QuickToken tk = new QuickToken(userInfo.getUsername(), userInfo.getPassword(), "", "");
        try {
            subject.login(tk);
            authState.setStatus(OAuthState.LOGGED_IN);
            stateService.put(authState.getSessionId(), authState);
        } catch (Exception e) {
            log.error("getAuthorizedStatus:> try to login failed by {} ", userInfo.getUsername(), e);
            tk.clear();
            throw RestletException.conflict("try to login failed");
        }

        return Result.data(authState.asResult()).success();
    }
}
