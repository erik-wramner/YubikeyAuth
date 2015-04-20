package com.codemint.example.yubi.jaas;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

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
 * Login module using user id, password and one time password with Yubico. This
 * is intended as an example and is not ready for production.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubiLoginModule implements LoginModule {

  private static final Logger _logger = LoggerFactory.getLogger(YubiLoginModule.class);
  private static final Map<String, UserAccount> _accountMap = UserAccount.createAccountMap("etc/user_accounts.txt");
  private final YubicoClient _yubicoClient = YubicoClientFactory.getYubicoClient();
  private final List<SimplePrincipal> _principals = new ArrayList<>();

  private static enum State {
    NEW, INITIALIZED, LOGIN_SUCCEEDED, COMMIT_SUCCEEDED
  };

  private State _state = State.NEW;

  private Subject _subject;
  private CallbackHandler _callbackHandler;

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
      Map<String, ?> options) {
    _logger.debug("Entering initialize state {}", _state);
    _subject = subject;
    _callbackHandler = callbackHandler;
    _state = State.INITIALIZED;
  }

  @Override
  public boolean login() throws LoginException {
    _logger.debug("Entering login state {}", _state);

    NameCallback nameCallback = new NameCallback("User:");
    PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
    try {
      _logger.debug("Invoking callback handler...");
      _callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
      _logger.debug("Callback handler returned");
    } catch (IOException e) {
      _logger.error("Callbackhandler failed", e);
      throw new LoginException("I/O error");
    } catch (UnsupportedCallbackException e) {
      _logger.error("Required standard callback not supported!", e);
      throw new LoginException("Required standard callback not supported");
    }

    String name = nameCallback.getName();
    char[] passwordArray = passwordCallback.getPassword();

    if (name != null && passwordArray != null) {
      _logger.debug("Authenticating {}", name);

      UserAccount userAccount = _accountMap.get(name);
      if (userAccount != null) {
        String bothPasswords = String.valueOf(passwordArray);
        int separatorPosition = bothPasswords.lastIndexOf('|');
        if (separatorPosition > 1) {
          String password = bothPasswords.substring(0, separatorPosition);
          String otp = bothPasswords.substring(separatorPosition + 1);

          _logger.debug("Password {} otp {}", password, otp);

          if (userAccount.getHashedPassword().equals(
              PasswordEncoder.encodePasswordForUser(name, userAccount.getSalt(), password))
              && YubicoClient.isValidOTPFormat(otp)) {
            try {
              _logger.debug("Verifying Yubikey for {}...", name);
              VerificationResponse response = _yubicoClient.verify(otp);
              if (response.isOk()) {
                if (response.getPublicId().equals(userAccount.getPublicYubiId())) {
                  loginSuccessful(userAccount);
                  return true;
                } else {
                  _logger.warn("Login attempt for {} with wrong Yubikey {}!", name, response.getPublicId());
                }
              } else {
                _logger.info("Failed to verify Yubikey for {}, response not OK", name);
              }
            } catch (YubicoValidationFailure e) {
              _logger.error("Validation failure for Yubikey", e);
            } catch (YubicoVerificationException e) {
              _logger.error("Failed to verify Yubikey - servers unreachable?", e);
            }
          } else {
            _logger.debug("Wrong password or bad format for OTP for {}", name);
          }
        }
      }
    }

    _logger.debug("Login failed");
    throw new LoginException("Login failed");
  }

  private void loginSuccessful(UserAccount userAccount) {
    _logger.debug("User {} with public id {} authenticated", userAccount.getEmail(), userAccount.getPublicYubiId());
    _principals.add(new SimplePrincipal(userAccount.getEmail()));
    for (String roleName : userAccount.getRoles()) {
      _principals.add(new SimplePrincipal(roleName));
    }
    _logger.debug("Prepared principals {}", _principals);
    _state = State.LOGIN_SUCCEEDED;
  }

  /**
   * Commit changes as the overall authentication was successful.
   * <p>
   * 
   * 
   * @return true if login and commit succeeded, false otherwise.O
   * @throws LoginException
   *           on errors.
   */
  @Override
  public boolean commit() throws LoginException {
    _logger.debug("Entering commit state {}", _state);

    if (_state == State.LOGIN_SUCCEEDED) {
      try {
        for (Principal principal : _principals) {
          _subject.getPrincipals().add(principal);
        }

        _logger.debug("Subject principals in commit: {}", _subject.getPrincipals());
      } catch (Exception e) {
        _logger.error("Commit failed", e);
        throw new LoginException("Commit failed!");
      }
      _state = State.COMMIT_SUCCEEDED;
      _logger.debug("Commit successful");
      return true;
    }
    return false;
  }

  /**
   * Overall authentication failed, clear state.
   * 
   * @return true if this module succeeded, false if it failed.
   * @throws LoginException
   *           on errors.
   */
  @Override
  public boolean abort() throws LoginException {
    _logger.debug("Entering abort state {}", _state);

    switch (_state) {
    case LOGIN_SUCCEEDED:
      // Fall through
    case COMMIT_SUCCEEDED:
      internalLogout();
      return true;
    default:
      return false;
    }
  }

  /**
   * Logout user and remove all principals added by {@link #commit()}.
   * 
   * @return true as this module should not be ignored.
   * @throws LoginException
   *           on errors.
   */
  @Override
  public boolean logout() throws LoginException {
    _logger.debug("Entering logout state {}", _state);
    internalLogout();
    return true;
  }

  private void internalLogout() {
    Set<Principal> subjectPrincipals = _subject.getPrincipals();
    for (Principal principal : _principals) {
      if (subjectPrincipals.contains(principal)) {
        subjectPrincipals.remove(principal);
      }
    }
    _principals.clear();
    _state = State.INITIALIZED;
  }
}
