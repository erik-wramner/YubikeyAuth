package com.codemint.example.yubi.jaspic;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

/**
 * This class functions as a kind of factory for {@link ServerAuthContext}
 * instances, which are delegates for the actual {@link ServerAuthModule} (SAM)
 * that we're after.
 *
 * Copied and adapted from <a href=
 * "http://arjan-tijms.omnifaces.org/2012/11/implementing-container-authentication.html"
 * >Arjan Tims</a> blog.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubiServerAuthConfig implements ServerAuthConfig {
  private final String layer;
  private final String appContext;
  private final CallbackHandler handler;
  private final Map<String, String> providerProperties;

  public YubiServerAuthConfig(String layer, String appContext, CallbackHandler handler,
      Map<String, String> providerProperties) {
    this.layer = layer;
    this.appContext = appContext;
    this.handler = handler;
    this.providerProperties = providerProperties;
  }

  @Override
  public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject,
      @SuppressWarnings("rawtypes") Map properties) throws AuthException {
    return new YubiServerAuthContext(handler);
  }

  @Override
  public String getMessageLayer() {
    return layer;
  }

  @Override
  public String getAuthContextID(MessageInfo messageInfo) {
    return appContext;
  }

  @Override
  public String getAppContext() {
    return appContext;
  }

  @Override
  public void refresh() {
  }

  @Override
  public boolean isProtected() {
    return false;
  }

  public Map<String, String> getProviderProperties() {
    return providerProperties;
  }
}