package com.codemint.example.yubi.shiro;

import java.io.Serializable;

import org.apache.shiro.authc.AuthenticationToken;

import com.codemint.example.yubi.util.PasswordEncoder;

/**
 * Example {@link AuthenticationToken} with support for both a regular password
 * and a one time password.
 * <p>
 * For simplicity the password is stored in clear text. That is NOT a good idea
 * for production code, it is better to store the password hash.
 * 
 * @author Erik Wramner, CodeMint
 */
public class UserPasswordAndOtpToken implements AuthenticationToken {
  private static final long serialVersionUID = 1L;
  private final String _userId;
  private final PasswordAndOtp _credentials;

  public UserPasswordAndOtpToken(String userId, String password, String otp) {
    _userId = userId;
    _credentials = new PasswordAndOtp(password, otp);
  }

  public String getUserId() {
    return _userId;
  }

  public String getHashedPassword(int salt) {
    return PasswordEncoder.encodePasswordForUser(_userId, salt, _credentials.getPassword());
  }

  public String getOtp() {
    return _credentials.getOtp();
  }

  @Override
  public Object getCredentials() {
    return _credentials;
  }

  @Override
  public Object getPrincipal() {
    return _userId;
  }

  @Override
  public String toString() {
    return "UserPasswordAndOtpToken[" + _userId + ", *, *]";
  }

  public static final class PasswordAndOtp implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String _password;
    private final String _otp;

    public PasswordAndOtp(String password, String otp) {
      _password = password;
      _otp = otp;
    }

    public String getPassword() {
      return _password;
    }

    public String getOtp() {
      return _otp;
    }
  }

}
