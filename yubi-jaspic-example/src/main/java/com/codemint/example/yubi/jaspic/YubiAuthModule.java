package com.codemint.example.yubi.jaspic;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codemint.example.yubi.data.UserAccount;
import com.codemint.example.yubi.util.PasswordEncoder;
import com.codemint.example.yubi.util.YubicoClientFactory;
import com.yubico.client.v2.VerificationResponse;
import com.yubico.client.v2.YubicoClient;

/**
 * Server Authentication Module (SAM) with user id, password and one time
 * password with Yubico. This code is intended as a simple example and is not
 * ready for production.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubiAuthModule implements ServerAuthModule {
  private static final String ORIGINAL_URI_SESSION_KEY = "com.codemint.example.yubi.jaspic.originalUri";
  private static final String USER_ACCOUNT_SESSION_KEY = "com.codemint.example.yubi.jaspic.userAccount";
  private static final String LOGIN_FAILED_SESSION_KEY = "com.codemint.example.yubi.jaspic.loginFailed";
  private static final String LOGIN_PAGE = "/login.jsp";
  private static final Logger _logger = LoggerFactory.getLogger(YubiAuthModule.class);
  private static final Map<String, UserAccount> _accountMap = UserAccount.createAccountMap("etc/user_accounts.txt");
  private final YubicoClient _yubicoClient = YubicoClientFactory.getYubicoClient();
  private CallbackHandler handler;

  @Override
  public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
      @SuppressWarnings("rawtypes") Map options) throws AuthException {
    _logger.debug("Enter initialize");
    this.handler = handler;
  }

  @Override
  public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject)
      throws AuthException {
    _logger.debug("Enter validateRequest");

    if (!requiresAuthentication(messageInfo)) {
      _logger.debug("Returning success, auth policy not mandatory");
      return AuthStatus.SUCCESS;
    }

    HttpServletRequest req = (HttpServletRequest) messageInfo.getRequestMessage();
    HttpServletResponse resp = (HttpServletResponse) messageInfo.getResponseMessage();

    try {
      UserAccount account = (UserAccount) req.getSession().getAttribute(USER_ACCOUNT_SESSION_KEY);
      if (account != null) {
        _logger.debug("Returning success, user already logged in");
        addPrincipalsToSubject(clientSubject, account);
        return AuthStatus.SUCCESS;
      }

      if (!req.getRequestURI().endsWith(LOGIN_PAGE)) {
        redirectToLoginPage(req, resp);
        return AuthStatus.SEND_CONTINUE;
      }

      if ("GET".equals(req.getMethod())) {
        forwardToLoginPage(req, resp, "GET request");
        return AuthStatus.SEND_CONTINUE;
      }

      String userName = req.getParameter("j_username");
      String password = req.getParameter("j_password");
      String otp = req.getParameter("j_otp");

      if (userName == null || password == null || otp == null) {
        _logger.debug("Returning failure, missing request parameter(s)");
        forwardToFailedLoginPage(req, resp, null);
        return AuthStatus.SEND_CONTINUE;
      }

      UserAccount userAccount = _accountMap.get(userName);
      if (userAccount != null
          && userAccount.getHashedPassword().equals(
              PasswordEncoder.encodePasswordForUser(userName, userAccount.getSalt(), password))
          && YubicoClient.isValidOTPFormat(otp)) {
        _logger.debug("Verifying Yubikey for {}...", userName);
        VerificationResponse response = _yubicoClient.verify(otp);
        if (response.isOk()) {
          if (response.getPublicId().equals(userAccount.getPublicYubiId())) {
            addPrincipalsToSubject(clientSubject, userAccount);
            req.getSession().setAttribute(USER_ACCOUNT_SESSION_KEY, userAccount);

            String originalUri = (String) req.getSession().getAttribute(ORIGINAL_URI_SESSION_KEY);
            if (originalUri != null) {
              _logger.debug("Login successful for {}, redirecting to {}", userName, originalUri);
              resp.sendRedirect(originalUri);
              return AuthStatus.SEND_CONTINUE;
            } else {
              _logger.debug("Login successful for {}, returning success", userName);
              return AuthStatus.SUCCESS;
            }
          } else {
            _logger.warn("Login attempt for {} with wrong Yubikey {}!", userName, response.getPublicId());
          }
        } else {
          _logger.info("Failed to verify Yubikey for {}, response not OK", userName);
        }
      }

      forwardToFailedLoginPage(req, resp, "authentication failed");
      return AuthStatus.SEND_CONTINUE;
    } catch (Exception e) {
      _logger.error("Authentication failed with exception", e);
      throw new AuthException(e.getMessage());
    }
  }

  private void redirectToLoginPage(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    _logger.debug("Redirecting to login page");
    saveUriIfFirstCall(req);
    resp.sendRedirect(LOGIN_PAGE);
  }

  private void addPrincipalsToSubject(Subject clientSubject, UserAccount account) throws IOException,
      UnsupportedCallbackException {
    handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, account.getEmail()),
        new GroupPrincipalCallback(clientSubject, account.getRoles().toArray(new String[0])) });
  }

  private void forwardToFailedLoginPage(HttpServletRequest req, HttpServletResponse resp, String reason)
      throws ServletException, IOException {
    req.setAttribute(LOGIN_FAILED_SESSION_KEY, Boolean.TRUE);
    forwardToLoginPage(req, resp, reason);
  }

  private void forwardToLoginPage(HttpServletRequest req, HttpServletResponse resp, String reason)
      throws ServletException, IOException {
    _logger.debug("Forwarding to login page: {}", reason);
    RequestDispatcher d = req.getRequestDispatcher(LOGIN_PAGE);
    d.forward(req, resp);
  }

  private void saveUriIfFirstCall(HttpServletRequest req) {
    if (req.getSession().getAttribute(ORIGINAL_URI_SESSION_KEY) == null) {
      String fullURI = getFullURI(req);
      _logger.debug("Saving uri {}", fullURI);
      req.getSession().setAttribute(ORIGINAL_URI_SESSION_KEY, fullURI);
    }
  }

  /**
   * A compliant implementation should return HttpServletRequest and
   * HttpServletResponse, so the delegation class {@link ServerAuthContext} can
   * choose the right SAM to delegate to. In this example there is only one SAM
   * and thus the return value actually doesn't matter here.
   */
  @Override
  public Class<?>[] getSupportedMessageTypes() {
    return new Class[] { HttpServletRequest.class, HttpServletResponse.class };
  }

  /**
   * WebLogic 12c calls this before Servlet is called, Geronimo v3 after, JBoss
   * EAP 6 and GlassFish 3.1.2.2 don't call this at all. WebLogic (seemingly)
   * only continues if SEND_SUCCESS is returned, Geronimo completely ignores
   * return value.
   */
  @Override
  public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
    return AuthStatus.SEND_SUCCESS;
  }

  @Override
  public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
  }

  private boolean requiresAuthentication(MessageInfo messageInfo) {
    return Boolean.valueOf((String) messageInfo.getMap().get("javax.security.auth.message.MessagePolicy.isMandatory"));
  }

  private static String getFullURI(HttpServletRequest request) {
    String queryString = request.getQueryString();
    if (queryString == null) {
      return request.getRequestURI().toString();
    } else {
      return request.getRequestURI() + "?" + queryString;
    }
  }
}