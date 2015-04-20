package com.codemint.example.yubi.filter;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codemint.example.yubi.data.UserAccount;
import com.codemint.example.yubi.util.PasswordEncoder;
import com.codemint.example.yubi.util.YubicoClientFactory;
import com.yubico.client.v2.VerificationResponse;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import com.yubico.client.v2.exceptions.YubicoVerificationException;

/**
 * Simple filter that redirects to login page if user has not authenticated
 * before accessing a protected page.
 * 
 * @author Erik Wramner, CodeMint
 */
public class AuthenticationFilter implements Filter {
  private final Logger _logger = LoggerFactory.getLogger(getClass());
  private YubicoClient _yubicoClient;
  private Map<String, UserAccount> _accountMap;

  @Override
  public synchronized void init(FilterConfig config) throws ServletException {
    _logger.info("Initializing...");
    _accountMap = UserAccount.createAccountMap("etc/user_accounts.txt");
    _yubicoClient = YubicoClientFactory.getYubicoClient();
    _logger.info("Initialized filter");
  }

  @Override
  public void destroy() {
    _logger.info("Destroyed filter");
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException,
      ServletException {
    if (req instanceof HttpServletRequest) {
      HttpServletRequest httpReq = (HttpServletRequest) req;

      if (!(isPublicPage(httpReq) || isUserAuthorized(httpReq))) {
        if (isUserAuthenticated(httpReq)) {
          ((HttpServletResponse) resp).sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        } else if (isLoginPage(httpReq)) {
          if (isFormSubmission(httpReq)) {
            UserAccount account = loginUser(req.getParameter("email"), req.getParameter("password"),
                req.getParameter("otp"));
            if (account != null) {
              httpReq.getSession(true).setAttribute("user", account);
              ((HttpServletResponse) resp).sendRedirect("/index.jsp");
              return;
            } else {
              slowDownBruteForceAttacksWithSleep();
              req.setAttribute("message", "Login failed, please try again!");
            }
          }
        } else {
          ((HttpServletResponse) resp).sendRedirect("/login.jsp");
          return;
        }
      }
    }
    chain.doFilter(req, resp);
  }

  private UserAccount loginUser(String email, String password, String otp) {
    if (email != null && password != null && otp != null) {
      UserAccount account = getAccountMap().get(email);

      if (account != null
          && account.getHashedPassword().equals(
              PasswordEncoder.encodePasswordForUser(email, account.getSalt(), password))
          && YubicoClient.isValidOTPFormat(otp)) {
        try {
          _logger.info("Verifying Yubikey for {}...", account.getEmail());
          VerificationResponse response = getYubicoClient().verify(otp);
          if (response.isOk()) {
            if (response.getPublicId().equals(account.getPublicYubiId())) {
              _logger.info("User {} with public id {} authenticated", account.getEmail(), response.getPublicId());
              return account;
            } else {
              _logger.warn("Login attempt for {} with wrong Yubikey {}!", account.getEmail(), response.getPublicId());
            }
          } else {
            _logger.info("Failed to verify Yubikey for {}, response not OK", account.getEmail());
          }
        } catch (YubicoValidationFailure e) {
          _logger.error("Validation failure for Yubikey", e);
        } catch (YubicoVerificationException e) {
          _logger.error("Failed to verify Yubikey - servers unreachable?", e);
        }
      }
    }
    return null;
  }

  /**
   * Check if the requested page is public.
   * 
   * @param req
   *          The request.
   * @return true if public.
   */
  private boolean isPublicPage(HttpServletRequest req) {
    // No public pages
    return false;
  }

  /**
   * Simple implementation, all authenticated users are authorized for all
   * pages.
   * 
   * @param req
   *          The servlet request.
   * @return true if logged on.
   */
  private boolean isUserAuthorized(HttpServletRequest req) {
    return isUserAuthenticated(req);
  }

  private boolean isUserAuthenticated(HttpServletRequest req) {
    HttpSession session = req.getSession(false);
    return session != null && session.getAttribute("user") != null;
  }

  private synchronized YubicoClient getYubicoClient() {
    return _yubicoClient;
  }

  private synchronized Map<String, UserAccount> getAccountMap() {
    return _accountMap;
  }

  private void slowDownBruteForceAttacksWithSleep() {
    try {
      Thread.sleep(2000L);
    } catch (InterruptedException e) {
    }
  }

  private boolean isFormSubmission(HttpServletRequest httpReq) {
    return "POST".equals(httpReq.getMethod());
  }

  private boolean isLoginPage(HttpServletRequest httpReq) {
    return httpReq.getRequestURI().startsWith("/login.jsp");
  }
}
