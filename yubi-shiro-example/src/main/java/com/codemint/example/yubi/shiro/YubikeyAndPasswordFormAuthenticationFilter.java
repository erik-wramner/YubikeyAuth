package com.codemint.example.yubi.shiro;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;

/**
 * Override the standard Shiro {@link FormAuthenticationFilter} in order to
 * create a {@link UserPasswordAndOtpToken} instance with a one-time password
 * rather than a {@link UsernamePasswordToken}.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubikeyAndPasswordFormAuthenticationFilter extends FormAuthenticationFilter {

  @Override
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    String userId = getUsername(request);
    String password = getPassword(request);
    String otp = request.getParameter("otp");
    return new UserPasswordAndOtpToken(userId, password, otp);
  }

}
