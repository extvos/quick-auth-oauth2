package plus.extvos.auth.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import plus.extvos.auth.config.QuickAuthConfig;
import plus.extvos.auth.dto.*;
import plus.extvos.auth.enums.AuthCode;
import plus.extvos.auth.service.*;
import plus.extvos.auth.utils.SessionUtil;
import plus.extvos.common.Assert;
import plus.extvos.common.Result;
import plus.extvos.common.ResultCode;
import plus.extvos.common.Validator;
import plus.extvos.common.exception.ResultException;
import plus.extvos.common.io.Resources;
import plus.extvos.common.utils.QrCode;
import plus.extvos.common.utils.QuickHash;
import plus.extvos.common.utils.SpringContextHolder;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.*;

/**
 * OAuth2
 * Procedure 1:
 * ( Browser    ) QrCode  ----------------&gt; Check Status ----------------------------------------&gt;        Login
 * ( Mobile App )         |-&gt; Access URL -&gt; Redirect to OAuth2 Login URL -&gt; Authorized URI -&gt; Login Process
 * Procedure 2:
 * ( Browser    ) URL -&gt; Access URL -&gt; Redirect to OAuth2 Login URL -&gt; Authorized URI -&gt; Login Process -&gt; Login
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

    @Autowired(required = false)
    private QuickAuthCallback quickAuthCallback;

    @Autowired(required = false)
    private UserRegisterHook userRegisterHook;

    @Autowired
    private ProviderService providerService;

    @Autowired
    private QuickAuthentication quickAuthentication;

    @Value("${quick.auth.base-url:http://localhost}")
    private String baseUrl;

    @Value("${quick.auth.authorized-url:}")
    private String authorizedUrl;

    @Value("${quick.auth.base.auto-register:false}")
    private boolean autoRegister;

    private OAuthProvider getProvider(String provider) throws ResultException {
        if (provider == null || provider.isEmpty()) {
            throw ResultException.badRequest("provider slug can not be empty");
        }
        OAuthProvider oAuthProvider = providerService.getProvider(provider);
        if (null == oAuthProvider) {
            throw ResultException.notFound("no provider named as '" + provider + "'");
        }
        return oAuthProvider;
    }

    private String getProviderLoginUri(OAuthProvider oAuthProvider, String redirectUri, String state) throws ResultException {
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = baseUrl;
            String prefix = SpringContextHolder.getProperties("server.servlet.context-path");
            log.debug("getProviderLoginUri:> prefix = {}", prefix);
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

    private String buildLoginUrl(OAuthProvider oAuthProvider, String redirectUri) throws ResultException {
        String gotoUrl = baseUrl;
        String prefix = SpringContextHolder.getProperties("server.servlet.context-path");
        log.debug("buildLoginUrl:> prefix = {}", prefix);
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
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, stateObj);
        gotoUrl += "?state=" + stateObj.getSessionId();
        try {
            if (redirectUri != null && !redirectUri.isEmpty()) {
                gotoUrl += "&redirectUri=" + URLEncoder.encode(redirectUri, "UTF-8");
            }
        } catch (UnsupportedEncodingException e) {
            throw ResultException.internalServerError(e.getMessage());
        }
        log.debug("buildLoginUrl:> {}", gotoUrl);
        return gotoUrl;
    }

    @ApiOperation(value = "第三方登录持列表")
    @GetMapping(value = "/providers")
    public Result<List<OAuthProvider>> getProviders() throws ResultException {
        List<OAuthProvider> m = new LinkedList<>(Arrays.asList(providerService.allProviders()));
        return Result.data(m).success();
    }

    @ApiOperation(value = "第三方通知")
    @RequestMapping(value = "/{provider}/notify")
    public Object goVerify(@PathVariable("provider") String provider,
                           @RequestParam(required = false) Map<String, Object> params,
                           @RequestBody(required = false) byte[] body) throws ResultException {
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
                                HttpServletResponse response) throws ResultException {
        OAuthProvider oAuthProvider = getProvider(provider);
        Subject subject = SecurityUtils.getSubject();
        String gotoUri = failureUri;
        Session session;
//        boolean external = false;
        if (state == null || state.isEmpty()) {
            session = subject.getSession(true);
            state = session.getId().toString();
        } else {
//            external = true;
            try {
                session = SecurityUtils.getSecurityManager().getSession(new DefaultSessionKey(state));
            } catch (ShiroException e) {
                buildAuthorizedResponse(oAuthProvider, response, -1, e.getMessage());
                return null;
            }
        }
        OAuthState stateObj = (OAuthState) session.getAttribute(OAuthState.OAUTH_STATE_KEY);
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
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, stateObj);
        gotoUri = getProviderLoginUri(oAuthProvider, redirectUri, state);
        String confirmPage = oAuthProvider.confirmPage("确认", quickAuthConfig.getSiteName(), gotoUri);
        if (confirmPage != null && !confirmPage.isEmpty()) {
            response.setDateHeader("Expires", 0);
            response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
            response.addHeader("Cache-Control", "post-check=0, pre-check=0");
            response.setHeader("Pragma", "no-cache");
            response.setContentType("text/html; charset=UTF-8");
            PrintWriter writer = null;
            try {
                writer = response.getWriter();
                writer.write(confirmPage);
                return null;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try {
            log.debug("goRedirect:> Redirecting to: {}", gotoUri);
            response.sendRedirect(gotoUri);
        } catch (IOException e) {

            log.error(">>", e);
        }
        return null;
    }

    @ApiOperation(value = "第三方登录跳转URL")
    @GetMapping(value = "/{provider}/code-url")
    public Result<String> getCodeUrl(@PathVariable("provider") String provider,
                                     @RequestParam(value = "redirectUri", required = false) String redirectUri) throws ResultException {
        OAuthProvider oAuthProvider = getProvider(provider);
        return Result.data(buildLoginUrl(oAuthProvider, redirectUri)).success();
    }

    @ApiOperation(value = "第三方登录跳转QRCODE", notes = "获取图片QRCODE，直接输出图片", position = 3)
    @RequestMapping(produces = MediaType.IMAGE_PNG_VALUE,
            value = "/{provider}/code-img", method = RequestMethod.GET)
    protected ModelAndView getCodeUrlImage(@PathVariable("provider") String provider,
                                           @RequestParam(value = "redirectUri", required = false) String redirectUri,
                                           @RequestParam(required = false) Integer size,
                                           HttpServletResponse response) throws ResultException, IOException {
        OAuthProvider oAuthProvider = getProvider(provider);
        String url = buildLoginUrl(oAuthProvider, redirectUri);
        log.debug("getCodeUrl: {}", url);
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
            if (quickAuthConfig.getLogoImage() != null && !quickAuthConfig.getLogoImage().isEmpty()) {
                File logo;
                if (quickAuthConfig.getLogoImage().startsWith("classpath:")) {
                    logo = Resources.getResourceAsFile(quickAuthConfig.getLogoImage().substring("classpath:".length()));
                } else {
                    logo = new File(quickAuthConfig.getLogoImage());
                }
                QrCode.size(size).logo(logo).format("png").content(url).write(out);
            } else {
                QrCode.size(size).format("png").content(url).write(out);
            }

            try {
                out.flush();
            } finally {
                out.close();
            }

        } catch (Exception e) {

            log.error(">>", e);
        }
        return null;
    }

    @ApiOperation(value = "第三方登录状态")
    @GetMapping(value = "/{provider}/auth-refresh")
    public Result<OAuthResult> getAuthorizedStatus(@PathVariable("provider") String provider) throws ResultException {
        log.debug("getAuthorizedStatus:>");
        OAuthState authState;
        Subject subject = SecurityUtils.getSubject();
        Session sess = subject.getSession();
        authState = (OAuthState) sess.getAttribute(OAuthState.OAUTH_STATE_KEY);
        if (null == authState) {
            log.debug("getAuthorizedStatus:> null authState");
            authState = new OAuthState(sess.getId().toString());
            authState.setStatus(OAuthState.INITIALIZED);
            return Result.data(authState.asResult()).success();
//            throw ResultException.notFound("state not exists");
        }
        if (subject.isAuthenticated() && quickAuthentication.userInfo() != null) {
            log.debug("getAuthorizedStatus:> subject.isAuthenticated");
            if (authState.getStatus() >= OAuthState.ID_PRESENTED && authState.getStatus() != OAuthState.LOGGED_IN) {
                UserInfo userInfo = authState.getUserInfo();
                if (null == userInfo) {
                    userInfo = quickAuthentication.userInfo();
                    authState.setUserInfo(userInfo);
                }
                authState.setStatus(OAuthState.LOGGED_IN);
                sess.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            }
        } else {
            if (authState.getStatus() >= OAuthState.ID_PRESENTED && authState.getStatus() < OAuthState.LOGGED_IN) {
                log.debug("getAuthorizedStatus:> authState.getStatus() = {}", authState.getStatus());
                UserInfo userInfo = authState.getUserInfo();
                if (userInfo != null) {
                    LoginResult result = quickAuthentication.loginImplicitly(userInfo, false);
                    if (null == result.getUserInfo()) {
                        throw ResultException.conflict("try to login failed");
                    } else {
                        userInfo = result.getUserInfo();
                        userInfo.setProvider(provider);
                        userInfo.setOpenId(authState.getOpenId());
                        userInfo.updateExtraInfo(authState.getExtraInfo());
                        authState.setStatus(OAuthState.LOGGED_IN);
                        authState.setExtraInfo(userInfo.getExtraInfo());
                        sess.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                        quickAuthentication.updateUserInfo(userInfo);
                    }
                }
            }
        }
//        if (authState.getUserInfo() != null) {
//            authState.getUserInfo().setPassword("");
//        }
        return Result.data(authState.asResult()).success();
    }

    private Result<OAuthResult> buildAuthorizedResponse(OAuthProvider provider, HttpServletResponse response, int ret, String err) {
        log.debug("buildAuthorizedResponse:> {} / {}", ret, err);
        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("text/html; charset=UTF-8");
        try {
            if (Validator.notEmpty(authorizedUrl)) {
                String gotoUri = authorizedUrl + "?ret=" + ret + "&err=" + err;
                log.debug("buildAuthorizedResponse:> Redirect to {} ", gotoUri);
                response.sendRedirect(gotoUri);
            } else {
                log.debug("buildAuthorizedResponse:> Generating output ...");
                PrintWriter writer = response.getWriter();
                writer.write(provider.resultPage(ret, err, quickAuthConfig.getSiteName()));
                writer.close();
            }
        } catch (IOException e) {
            log.error(">>", e);
        }
        return null;
    }

    @ApiOperation(value = "用户登录并绑定(OAuth)", notes = "扫码后未绑定用户")
    @PostMapping(value = "/{provider}/login")
    public Result<UserInfo> loginUser(@PathVariable("provider") String provider,
                                      @RequestParam(value = "username", required = false) String username,
                                      @RequestParam(value = "email", required = false) String email,
                                      @RequestParam(value = "cellphone", required = false) String cellphone,
                                      @RequestParam(value = "verifier", required = false) String verifier,
                                      @RequestParam(value = "password", required = false) String password,
                                      @RequestParam(value = "salt", required = false) String salt,
                                      @RequestParam(value = "algorithm", required = false) String algorithm,
                                      @RequestParam(value = "captcha", required = false) String captcha,
                                      @RequestBody(required = false) Map<String, String> params) throws ResultException {
        if (Validator.notEmpty(params)) {
            username = params.getOrDefault("username", username);
            email = params.getOrDefault("email", email);
            cellphone = params.getOrDefault("cellphone", cellphone);
            verifier = params.getOrDefault("verifier", verifier);
            password = params.getOrDefault("password", password);
            captcha = params.getOrDefault("captcha", captcha);
            salt = params.getOrDefault("salt", salt == null ? "" : salt);
            algorithm = params.getOrDefault("algorithm", algorithm == null ? "" : algorithm);
        }
        log.debug("loginUser:> {},{},{},{},{}", username, password, algorithm, salt, captcha);
//        OAuthProvider oAuthProvider = getProvider(provider);
        quickAuthentication.validateCaptcha(captcha, quickAuthConfig.isCaptchaRequired());
        LoginResult loginResult;
        if (Validator.notEmpty(username)) {
            loginResult = quickAuthentication.loginByUsername(username, password, algorithm, salt, false);
        } else if (Validator.notEmpty(email)) {
            if (Validator.notEmpty(verifier)) {
                loginResult = quickAuthentication.loginByEmail(email, verifier, false);
            } else {
                loginResult = quickAuthentication.loginByEmail(email, password, algorithm, salt, false);
            }

        } else if (Validator.notEmpty(cellphone)) {
            if (Validator.notEmpty(verifier)) {
                loginResult = quickAuthentication.loginByCellphone(cellphone, verifier, false);
            } else {
                loginResult = quickAuthentication.loginByCellphone(cellphone, password, algorithm, salt, false);
            }

        } else {
            throw ResultException.badRequest("username of email or cellphone required");
        }
        if (loginResult.getResult() != ResultCode.OK) {
            throw ResultException.make(loginResult.getResult(), loginResult.getError());
        }
        UserInfo userInfo = loginResult.getUserInfo();
        if (null == userInfo) {
            throw ResultException.forbidden("login failed ???");
        }
        try {
            Session session = SecurityUtils.getSubject().getSession();
            Assert.notNull(session, ResultException.forbidden("not in session"));
            OAuthState authState = (OAuthState) session.getAttribute(OAuthState.OAUTH_STATE_KEY);
            Assert.notNull(authState, ResultException.forbidden("not in oauth session"));
            Assert.notEmpty(authState.getOpenId(), ResultException.forbidden("openId presented in oauth session"));
            Assert.equals(authState.getStatus(), OAuthState.NEED_REGISTER, ResultException.forbidden("not in NEED_REGISTER state"));
            OAuthInfo oAuthInfo = openidResolver.register(provider, authState.getOpenId(), authState.getUnionId(), userInfo.getUsername(), userInfo.getPassword(), authState.getExtraInfo());
            Assert.notNull(oAuthInfo, ResultException.serviceUnavailable("create user failed"));
            Assert.notNull(oAuthInfo.getUserId(), ResultException.serviceUnavailable("create user failed"));
            authState.setAuthInfo(oAuthInfo);
            userInfo.setOpenId(oAuthInfo.getOpenId());
            userInfo.setUnionId(oAuthInfo.getUnionId());
            userInfo.setProvider(provider);
            userInfo.updateExtraInfo(authState.getExtraInfo());
            authState.setUserInfo(userInfo);
            authState.setStatus(OAuthState.LOGGED_IN);
            session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            quickAuthentication.updateUserInfo(userInfo);
        } catch (Exception e) {
            log.error("attache user open account failed:> ", e);
            SecurityUtils.getSubject().logout();
            throw ResultException.internalServerError("attache user open account failed");
        }
        return Result.data(userInfo).success();
    }

    @ApiOperation(value = "用户注册并绑定(OAuth)", notes = "扫码后未注册用户")
    @PostMapping(value = "/{provider}/register")
    public Result<UserInfo> registerUser(@PathVariable("provider") String provider,
                                         @RequestParam(value = "username", required = false) String username,
                                         @RequestParam(value = "password", required = false) String password,
                                         @RequestParam(value = "phoneNumber", required = false) String phoneNumber,
                                         @RequestParam(value = "captcha", required = false) String captcha,
                                         @RequestParam(value = "email", required = false) String email,
                                         @RequestParam(value = "verifier", required = false) String verifier,
                                         @RequestBody(required = false) Map<String, Object> params) throws ResultException {
        if (!quickAuthConfig.isRegisterAllowed()) {
            throw ResultException.forbidden("registration not allowed");
        }
        OAuthProvider oAuthProvider = getProvider(provider);
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        Assert.notNull(session, ResultException.forbidden("not in session"));
        OAuthState authState = (OAuthState) session.getAttribute(OAuthState.OAUTH_STATE_KEY);
        Assert.notNull(authState, ResultException.forbidden("not in oauth session"));
//        Assert.notNull(authState.getAuthInfo(), ResultException.forbidden("no authInfo presented in oauth session"));
        Assert.notEmpty(authState.getOpenId(), ResultException.forbidden("openId presented in oauth session"));
        Assert.equals(authState.getStatus(), OAuthState.NEED_REGISTER, ResultException.forbidden("not in NEED_REGISTER state"));
//        Assert.notEmpty(params, ResultException.forbidden("invalid empty request body"));
        if (quickAuthConfig.isRegisterCaptchaRequired() || captcha != null) {
            Assert.notEmpty(captcha, new ResultException(AuthCode.CAPTCHA_REQUIRED, "Captcha required!"));
            SessionUtil.validateCaptcha(captcha, new ResultException(AuthCode.INCORRECT_CAPTCHA, "Incorrect captcha"));
        }
        if (quickAuthConfig.isRegisterVerifierRequired() || verifier != null) {
            Assert.notEmpty(verifier, new ResultException(AuthCode.VERIFIER_REQUIRED, "Verifier required!"));
            SessionUtil.validateVerifier(verifier, new ResultException(AuthCode.INCORRECT_VERIFIER, "Incorrect verifier"));
        }
        String[] perms = null;
        String[] roles = null;
        short status = 0;
        if (Validator.notEmpty(params)) {
            username = params.getOrDefault("username", username).toString();
            password = params.getOrDefault("password", password).toString();
            phoneNumber = params.getOrDefault("phoneNumber", phoneNumber == null ? "" : phoneNumber).toString();
            email = params.getOrDefault("email", email == null ? "" : email).toString();
            params.remove("username");
            params.remove("password");
        } else {
            params = new HashMap<>();
        }
        if (null != phoneNumber && !params.containsKey("phoneNumber")) {
            params.put("phoneNumber", phoneNumber);
        }
        if (null != email && !params.containsKey("email")) {
            params.put("email", email);
        }
        Assert.notEmpty(username, ResultException.forbidden("invalid empty username"));
        Assert.notEmpty(password, ResultException.forbidden("invalid empty password"));

        if (userRegisterHook != null) {
            if (!userRegisterHook.preRegister(username, password, params, UserRegisterHook.OPEN)) {
                throw ResultException.forbidden("not allowed to register user");
            }
            perms = userRegisterHook.defaultPermissions(UserRegisterHook.OPEN);
            roles = userRegisterHook.defaultRoles(UserRegisterHook.OPEN);
            status = userRegisterHook.defaultStatus(UserRegisterHook.OPEN);
        } else {
            status = quickAuthConfig.getDefaultStatus();
            perms = quickAuthConfig.getDefaultPermissions().split(",");
            roles = quickAuthConfig.getDefaultRoles().split(",");
        }
        UserInfo u = quickAuthService.getUserByName(username, false);
        if (u != null) {
            throw ResultException.conflict("user with username '" + username + "' already exists");
        }
        if (null != authState.getExtraInfo()) {
            params.putAll(authState.getExtraInfo());
        }
        Serializable userId = quickAuthService.createUserInfo(username, password, status, perms, roles, params);
        Assert.notNull(userId, ResultException.serviceUnavailable("create user failed"));
        OAuthInfo oAuthInfo = openidResolver.register(provider, authState.getOpenId(), authState.getUnionId(), username, password, params);
        Assert.notNull(oAuthInfo.getUserId(), ResultException.serviceUnavailable("create user failed"));
        UserInfo userInfo = new UserInfo(userId, username, password, phoneNumber, email);
        if (Validator.notEmpty(params)) {
            if (params.containsKey("email")) {
                userInfo.setEmail(params.get("email").toString());
            }
            if (params.containsKey("phoneNumber")) {
                userInfo.setCellphone(params.get("phoneNumber").toString());
            }
        }
        authState.setAuthInfo(oAuthInfo);
        userInfo.setOpenId(oAuthInfo.getOpenId());
        userInfo.setUnionId(oAuthInfo.getUnionId());
        userInfo.setProvider(provider);
        authState.setUserInfo(userInfo);
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
        return Result.data(userInfo).success();
    }

    /**
     * @param provider name of provider
     * @param code     code in string
     * @param state    in string
     * @param via      in string
     * @param response http response
     * @return result of OAuthResult
     * @throws ResultException when error
     */
    @ApiOperation(value = "第三方登录回调", notes = "via should be 'SESSIONKEY' when calling via Session Key mode")
    @GetMapping(value = "/{provider}/authorized")
    public Result<OAuthResult> authorized(@PathVariable("provider") String provider,
                                          @RequestParam(value = "code") String code,
                                          @RequestParam(value = "state", required = false) String state,
                                          @RequestParam(value = "via", required = false) String via,
                                          HttpServletResponse response) throws ResultException {
        log.debug("authorized:> code={},state={}", code, state);
        Subject subject = SecurityUtils.getSubject();
        Session session;
        boolean external = false;
        OAuthProvider oAuthProvider = getProvider(provider);
        if (Validator.isEmpty(code)) {
            throw ResultException.forbidden("authorization not accepted");
        }
        if (Validator.isEmpty(state)) {
            session = subject.getSession(true);
            state = session.getId().toString();
        } else {
            external = true;
            session = SecurityUtils.getSecurityManager().getSession(new DefaultSessionKey(state));
        }
        OAuthState authState = (OAuthState) session.getAttribute(OAuthState.OAUTH_STATE_KEY);
        if (authState == null || Validator.isEmpty(authState.getSessionId())) {
            log.debug("authorized:> state of '{}' not exists, make a new one...", state);
            authState = new OAuthState(state);
        }
        if (authState.getStatus() < OAuthState.INITIALIZED) {
            if (external) {
                return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), authState.getError());
            } else {
                return Result.data(authState.asResult()).success();
            }
        }
        if (authState.getStatus() > OAuthState.INFO_PRESENTED) {
            if (external) {
                return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), "");
            } else {
                return Result.data(authState.asResult()).success();
            }
        }
        try {
            authState = oAuthProvider.authorized(code, state, via, authState);
        } catch (ResultException e) {
            authState.setStatus(OAuthState.FAILED);
            authState.setError(e.getMessage());
            session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            if (external) {
                return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), e.getMessage());
            } else {
                throw e;
            }
        }
        authState.setStatus(OAuthState.ACCEPTED);
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
        String currentUsername = null;
        Serializable currentUserId = null;
        if (authState.getUserInfo() != null) {
            currentUsername = authState.getUserInfo().getUsername();
            currentUserId = authState.getUserInfo().getUserId();
        }
        Assert.notEmpty(authState.getOpenId(), ResultException.serviceUnavailable("openid not provided"));
        Map<String, Object> extraInfo = authState.getExtraInfo();
//        String openId = authState.getOpenId();
//        authState.setOpenId(openId);
        authState.setStatus(OAuthState.ID_PRESENTED);
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
        OAuthInfo authInfo = null;
        try {
            authInfo = openidResolver.resolve(provider, authState.getOpenId(), authState.getUnionId(), currentUserId, extraInfo);
        } catch (ResultException e) {
            authState.setStatus(OAuthState.FAILED);
            authState.setError(e.getMessage());
            session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            if (external) {
                return buildAuthorizedResponse(oAuthProvider, response, OAuthState.FAILED, e.getMessage());
            } else {
                throw ResultException.forbidden(e.getMessage());
            }
        }
        if (null == authInfo) {  // Not getting user info, need to register...
            if (null != currentUserId) { // Attach to existing user
                try {
                    authInfo = openidResolver.register(provider, authState.getOpenId(), authState.getUnionId(), currentUsername, null, extraInfo);
                    authState.setExtraInfo(authInfo.getExtraInfo());
                    authState.setStatus(OAuthState.LOGGED_IN);
                    session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                    UserInfo userInfo = authState.getUserInfo();
                    userInfo = quickAuthService.fillUserInfo(userInfo);
                    userInfo.setProvider(provider);
                    userInfo.setOpenId(authState.getOpenId());
                    userInfo.setUnionId(authState.getUnionId());
                    userInfo.updateExtraInfo(authInfo.getExtraInfo());
                    authState.setUserInfo(userInfo);
                    authState.setAuthInfo(authInfo);
                    session.setAttribute(UserInfo.USER_INFO_KEY, userInfo);
                    session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                } catch (ResultException e) {
                    log.warn("authorized:> ", e);
                    authState.setStatus(OAuthState.FAILED);
                    authState.setError(e.getMessage());
                    session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                    if (external) {
                        return buildAuthorizedResponse(oAuthProvider, response, OAuthState.FAILED, e.getMessage());
                    } else {
                        throw ResultException.forbidden(e.getMessage());
                    }
                }
            } else {
                authState.setStatus(OAuthState.NEED_REGISTER);
                session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            }
            if (external) {
                return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), "");
            } else {
                return Result.data(authState.asResult()).success();
            }
        } else if (Validator.notEmpty(extraInfo)) {
            log.debug("authorized:> userInfo of {} resolved as {}, try to update...", authState.getOpenId(), authInfo.getUserId());
            authInfo = openidResolver.update(provider, authState.getOpenId(), authState.getUnionId(), authInfo.getUserId(), extraInfo);
        }
        UserInfo userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
        userInfo.setProvider(provider);
        userInfo.setOpenId(authState.getOpenId());
        userInfo.setUnionId(authState.getUnionId());
        userInfo.setExtraInfo(authInfo.getExtraInfo());
        authState.setUserInfo(userInfo);
        authState.setAuthInfo(authInfo);
        authState.setStatus(OAuthState.INFO_PRESENTED);
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
//        if (quickAuthConfig.isPhoneRequired() && Validator.isEmpty(userInfo.getCellphone())) {
//            log.debug("authorized:> use cellphone not presented ...");
//            if (external) {
//                return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), "");
//            } else {
//                return Result.data(authState.asResult()).success();
//            }
//        }
        // Do the login if state in current session.
        if (authState.getSessionId().equals(subject.getSession().getId().toString())) {
            log.debug("authorized:> trying to login account {} / {}  / {} ...", userInfo.getUsername(), authState.getOpenId(), userInfo.getPassword());
            LoginResult loginResult = quickAuthentication.loginImplicitly(userInfo, false);
            if (null == loginResult.getUserInfo()) {
                if (external) {
                    return buildAuthorizedResponse(oAuthProvider, response, OAuthState.FAILED, "try to login failed");
                } else {
                    throw ResultException.conflict("try to login failed");
                }
            } else {
                authState.setStatus(OAuthState.LOGGED_IN);
                authState.setExtraInfo(authInfo.getExtraInfo());
                session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                return Result.data(authState.asResult()).success();
            }
        }
        if (external) {
            return buildAuthorizedResponse(oAuthProvider, response, authState.getStatus(), "");
        } else {
            return Result.data(authState.asResult()).success();
        }
    }

    @ApiOperation(value = "第三方会话更新", notes = "在第三方认证调用authorized接口没有完成登录时，通过更新数据完成注册登录流程，目前用于小程序认证登录")
    @PostMapping(value = "/{provider}/session-update")
    public Result<OAuthResult> authorizedUpdate(@PathVariable("provider") String provider,
                                                @RequestParam(required = false) Map<String, Object> params,
                                                @RequestBody(required = false) Map<String, Object> objectMap) throws ResultException {
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
        Assert.notEmpty(requestParams, ResultException.badRequest("empty request"));
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        if (null == session) {
            throw ResultException.forbidden("not in a valid session.");
        }
        String state = session.getId().toString();
        OAuthProvider oAuthProvider = getProvider(provider);
        OAuthState authState = (OAuthState) session.getAttribute(OAuthState.OAUTH_STATE_KEY);
        if (authState == null || Validator.isEmpty(authState.getSessionId())) {
            throw ResultException.unauthorized("Session state of '" + state + "' not exists");
        }
        log.debug("registerSession:> authState: {} / {}", authState, requestParams);
        Assert.greaterThan(authState.getStatus(), OAuthState.ACCEPTED, ResultException.forbidden("session not in state"));

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
            openidResolver.update(provider, authState.getOpenId(), authState.getUnionId(), authInfo == null ? null : authInfo.getUserId(), extraInfo);
            return Result.data(authState.asResult()).success();
        }
        // TODO: register user .... ???
        // Present status
        authState.setStatus(OAuthState.INFO_PRESENTED);
        session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);

        // get userInfo by openId if userInfo not presented
        if (null == authInfo) {
            authInfo = openidResolver.resolve(provider, authState.getOpenId(), authState.getUnionId(), null, extraInfo);
        }

        if (null == userInfo) {
            if (null != authInfo) {
                userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
            } else if (Validator.notEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
                userInfo = quickAuthService.getUserByPhone(extraInfo.get(OAuthProvider.PHONE_NUMBER_KEY).toString(), true);
            }
        }
        // get userInfo by phone number if userInfo not presented and phone is ready
//        if (null == userInfo && Validator.notEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
//            userInfo = quickAuthService.getUserByPhone(extraInfo.get(OAuthProvider.PHONE_NUMBER_KEY).toString(), false);
//        }

//        if (quickAuthConfig.isPhoneRequired()) {
//            if (Validator.isEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
//                // phone required
//                log.debug("registerSession:> phone required, check phone number ...");
//                return Result.data(authState.asResult()).success();
//            }
//        }


        // try to register user if userInfo not presented
        if (null == userInfo) {
//            if (!Validator.isEmpty(extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString())) {
//                String phone = extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, "").toString();
//                userInfo = quickAuthService.getUserByPhone(phone, true);
//            }
//            if (null == userInfo) {
            if (!autoRegister) {
                authState.setStatus(OAuthState.NEED_REGISTER);
                session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
                return Result.data(authState.asResult()).success();
            } else {
                username = extraInfo.getOrDefault(OAuthProvider.PHONE_NUMBER_KEY, authState.getOpenId()).toString();
                password = QuickHash.md5().hash(authState.getOpenId()).hex();
                Serializable userId = quickAuthService.createUserInfo(username, password, (short) 1, null, null, extraInfo);
                userInfo = quickAuthService.getUserById(userId, true);
                authInfo = openidResolver.register(provider, authState.getOpenId(), authState.getUnionId(), username, password, extraInfo);
            }

//            }
//            authInfo = openidResolver.register(provider, authState.getOpenId(), userInfo.getUsername(), userInfo.getPassword(), extraInfo);
//            if (!autoRegister) {
//                log.debug("registerSession:> not allow to auto register, return status 403");
//                throw ResultException.forbidden("not allowed to login");
//            } else {
//                log.debug("registerSession:> auto register user ...");
//                authInfo = openidResolver.register(provider, authState.getOpenId(), username, password, extraInfo);
//                userInfo = quickAuthService.getUserById(authInfo.getUserId(), true);
//            }
        } else {
            log.debug("registerSession:> resolved used: {}, update ...", userInfo.getUsername());
        }
        // trying to login
        log.debug("registerSession:> try to logging user '{}' ... ", userInfo.getUsername());
        LoginResult loginResult = quickAuthentication.loginImplicitly(userInfo, false);
        if (null == loginResult.getUserInfo()) {
            throw ResultException.conflict("try to login failed");
        } else {
//            if (null != authInfo) {
//                authInfo = openidResolver.update(provider, authState.getOpenId(), userInfo.getUserId(), extraInfo);
//                extraInfo.putAll(authInfo.getExtraInfo());
//            } else {
//                authInfo = new OAuthInfo(userInfo.getUserId(), authState.getOpenId(), provider);
//                authInfo.setExtraInfo(extraInfo);
//            }
            authInfo = openidResolver.update(provider, authState.getOpenId(), authState.getUnionId(), userInfo.getUserId(), extraInfo);
            extraInfo.putAll(authInfo.getExtraInfo());
            authState.setUserInfo(userInfo);
            authState.setAuthInfo(authInfo);
            authState.setExtraInfo(extraInfo);

            authInfo.setUserId(userInfo.getUserId());
            authState.setOpenId(authState.getOpenId());
            authState.setStatus(OAuthState.LOGGED_IN);
//            authState.setExtraInfo(authInfo.getExtraInfo());
            session.setAttribute(OAuthState.OAUTH_STATE_KEY, authState);
            return Result.data(authState.asResult()).success();
        }

//        return Result.data(authState.asResult()).success();
    }
}
