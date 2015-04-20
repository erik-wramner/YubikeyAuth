package com.codemint.example.yubi.jaas;

import java.io.IOException;
import java.lang.reflect.Method;
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
 * Jetty-specific login module using user id, password and one time password
 * with Yubico. This is intended as an example and is not ready for production.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubiNonPortableLoginModule implements LoginModule {

  private static final Logger _logger = LoggerFactory.getLogger(YubiNonPortableLoginModule.class);
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
    _logger.debug("Initializing login module for {}", subject);
    _subject = subject;
    _callbackHandler = callbackHandler;
    _state = State.INITIALIZED;
  }

  @Override
  public boolean login() throws LoginException {
    _logger.debug("Entering login state {}", _state);

    if (_callbackHandler == null) {
      throw new LoginException("Callback handler null");
    }

    NameCallback nameCallback = new NameCallback("User:");
    PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
    RequestCallbackAdapter requestCallbackAdapter = createRequestCallback();

    try {
      _logger.debug("Invoking callback handler...");
      _callbackHandler.handle(new Callback[] { nameCallback, passwordCallback, requestCallbackAdapter.getCallback() });
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
    String otp = requestCallbackAdapter.getOtpParameterValue();

    if (name != null && passwordArray != null && otp != null) {
      _logger.debug("Authenticating {}", name);

      UserAccount userAccount = _accountMap.get(name);

      if (userAccount.getHashedPassword().equals(
          PasswordEncoder.encodePasswordForUser(name, userAccount.getSalt(), new String(passwordArray)))
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

    _logger.debug("Login failed");
    throw new LoginException("Login failed");
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

  /**
   * Create implementation-specific callback adapter for accessing request
   * parameters. Most servers provide this, but all implementations are
   * different.
   * 
   * @return request callback adapter.
   * @throws LoginException
   *           if no supported callback is found.
   */
  private RequestCallbackAdapter createRequestCallback() throws LoginException {
    try {
      _logger.debug("Looking for Jetty request callback...");
      Class<?> requestCallbackClass = Class.forName("org.eclipse.jetty.jaas.callback.RequestParameterCallback");
      Method setParameterNameMethod = requestCallbackClass.getDeclaredMethod("setParameterName", String.class);
      Method getParameterValuesMethod = requestCallbackClass.getDeclaredMethod("getParameterValues");
      Callback callback = Callback.class.cast(requestCallbackClass.newInstance());
      setParameterNameMethod.invoke(callback, "j_otp");
      JettyRequestCallbackAdapter adapter = new JettyRequestCallbackAdapter(callback, getParameterValuesMethod);
      _logger.debug("Successfully created Jetty request callback adapter");
      return adapter;
    } catch (Exception e) {
      // Move on to next implementation
      _logger.debug("Failed to create request callback for Jetty", e);
    }

    // Add similar adapters for WebSphere, GlassFish, ...

    throw new LoginException("No supported request callback implementation found!");
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
   * Adapter with request callback and with method for extracting OTP parameter.
   * 
   * @author Erik Wramner
   */
  private static abstract class RequestCallbackAdapter {
    protected final Callback _callback;

    protected RequestCallbackAdapter(Callback callback) {
      _callback = callback;
    }

    public Callback getCallback() {
      return _callback;
    }

    public abstract String getOtpParameterValue();
  }

  /**
   * Jetty-specific adapter.
   * 
   * @author Erik Wramner
   */
  private static class JettyRequestCallbackAdapter extends RequestCallbackAdapter {
    private final Method _getParameterValuesMethod;

    protected JettyRequestCallbackAdapter(Callback callback, Method getParameterValuesMethod) {
      super(callback);
      _getParameterValuesMethod = getParameterValuesMethod;
    }

    @Override
    public String getOtpParameterValue() {
      try {
        List<?> values = (List<?>) _getParameterValuesMethod.invoke(_callback);
        if (values != null && values.size() == 1) {
          return (String) values.get(0);
        }
      } catch (Exception e) {
        // Ignore
      }
      return null;
    }
  }
}
