package com.codemint.example.yubi.shiro;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codemint.example.yubi.data.UserAccount;
import com.yubico.client.v2.VerificationResponse;
import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import com.yubico.client.v2.exceptions.YubicoVerificationException;

/**
 * Example {@link AuthorizingRealm} that uses passwords and Yubikey one time
 * passwords.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubikeyAndPasswordAuthorizingRealm extends AuthorizingRealm {
  private final Logger _logger = LoggerFactory.getLogger(getClass());
  private final Map<String, UserAccount> _accountMap = createAccountMap();
  private final YubicoClient _yubicoClient = createYubicoClient();

  /**
   * Get authorization information for a collection of principals. When there is
   * only a single realm (ours) we can safely use the primary principal.
   * 
   * @param principalCollection
   *          The principal collection.
   * @return authorization info with granted roles.
   */
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
    UserAccount account = _accountMap.get(principalCollection.getPrimaryPrincipal());
    return new SimpleAuthorizationInfo(account != null ? account.getRoles() : new java.util.TreeSet<String>());
  }

  /**
   * Authenticate a user with password and one-time password.
   * 
   * @param token
   *          The token, which must be a {@link UserPasswordAndOtpToken}.
   * @return authentication info or null.
   * @throws AuthenticationException
   *           on errors.
   */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    if (!supports(token)) {
      throw new IllegalArgumentException("Token not supported!");
    }

    UserPasswordAndOtpToken t = (UserPasswordAndOtpToken) token;
    UserAccount account = _accountMap.get(t.getUserId());

    if (account != null && account.getHashedPassword().equals(t.getHashedPassword(account.getSalt()))) {
      if (YubicoClient.isValidOTPFormat(t.getOtp())) {
        try {
          _logger.info("Verifying Yubikey for {}...", account.getEmail());

          VerificationResponse response = _yubicoClient.verify(t.getOtp());

          if (response.isOk()) {
            if (response.getPublicId().equals(account.getPublicYubiId())) {
              _logger.info("User {} with public id {} authenticated", account.getEmail(), response.getPublicId());
              return new SimpleAccount(t.getPrincipal(), t.getCredentials(), getName(), account.getRoles(),
                  new HashSet<Permission>());
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

    _logger.info("Returning null (login failed)");
    return null;
  }

  /**
   * Override to support only {@link UserPasswordAndOtpToken} tokens.
   * 
   * @param token
   *          The token.
   */
  @Override
  public boolean supports(AuthenticationToken token) {
    return token instanceof UserPasswordAndOtpToken;
  }

  /**
   * Create a map from user identities to user accounts based on a text file.
   * 
   * @return map with all accounts.
   */
  private static Map<String, UserAccount> createAccountMap() {
    Map<String, UserAccount> map = new HashMap<>();
    try {
      for (UserAccount account : UserAccount.readAccounts(new File("etc/user_accounts.txt"))) {
        map.put(account.getEmail(), account);
      }
      return map;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Create a Yubico client with key and client id from a property file.
   * <p>
   * Visit <a href="https://upgrade.yubico.com/getapikey">Yubico</a> to get your
   * own key.
   * 
   * @return client.
   */
  private static YubicoClient createYubicoClient() {
    InputStream is = null;
    try {
      is = YubikeyAndPasswordAuthorizingRealm.class.getResourceAsStream("/yubico.properties");
      if (is != null) {
        Properties props = new Properties();
        props.load(is);
        return YubicoClient.getClient(Integer.valueOf(props.getProperty("client_id")), props.getProperty("secret_key"));
      } else {
        throw new IllegalStateException("Failed to read yubico.properties!");
      }
    } catch (IOException e) {
      throw new RuntimeException("Failed to read yubico.properties!", e);
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (IOException e) {
        }
      }
    }
  }
}
