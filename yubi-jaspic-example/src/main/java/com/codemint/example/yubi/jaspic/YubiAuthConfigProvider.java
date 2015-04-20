package com.codemint.example.yubi.jaspic;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ServerAuthConfig;

/**
 * This class (our factory-factory) basically returns our factory from the right
 * method.
 * 
 * Copied and adapted from <a href=
 * "http://arjan-tijms.omnifaces.org/2012/11/implementing-container-authentication.html"
 * >Arjan Tims</a> blog.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubiAuthConfigProvider implements AuthConfigProvider {
  private static final String CALLBACK_HANDLER_PROPERTY_NAME = "authconfigprovider.client.callbackhandler";
  private Map<String, String> providerProperties;

  /**
   * Default constructor.
   */
  public YubiAuthConfigProvider() {
  }

  /**
   * Constructor with signature and implementation that's required by API.
   *
   * @param properties
   * @param factory
   */
  public YubiAuthConfigProvider(Map<String, String> properties, AuthConfigFactory factory) {
    this.providerProperties = properties;
    if (factory != null) {
      factory.registerConfigProvider(this, null, null, "Auto registration");
    }
  }

  /**
   * The actual factory method that creates the factory used to eventually
   * obtain the delegate for a SAM.
   */
  @Override
  public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler handler)
      throws AuthException, SecurityException {
    return new YubiServerAuthConfig(layer, appContext, handler == null ? createDefaultCallbackHandler() : handler,
        providerProperties);
  }

  /**
   * Creates a default callback handler via the system property
   * "authconfigprovider.client.callbackhandler", as seemingly required by the
   * API (API uses wording "may" create default handler).
   *
   * @return callback handler.
   * @throws AuthException
   */
  private CallbackHandler createDefaultCallbackHandler() throws AuthException {
    String callBackClassName = System.getProperty(CALLBACK_HANDLER_PROPERTY_NAME);

    if (callBackClassName == null) {
      throw new AuthException("No default handler set via system property: " + CALLBACK_HANDLER_PROPERTY_NAME);
    }

    try {
      return (CallbackHandler) Thread.currentThread().getContextClassLoader().loadClass(callBackClassName)
          .newInstance();
    } catch (Exception e) {
      throw new AuthException(e.getMessage());
    }
  }

  @Override
  public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler)
      throws AuthException, SecurityException {
    return null;
  }

  @Override
  public void refresh() {
  }
}