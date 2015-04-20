package com.codemint.example.yubi.jaspic;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * This class registers our JASPIC Server Authentication Module using the
 * factory-factory-factory obtained from {@link AuthConfigFactory}.
 * 
 * Copied and adapted from <a href=
 * "http://arjan-tijms.omnifaces.org/2012/11/implementing-container-authentication.html"
 * >Arjan Tims</a> blog.
 * 
 * @author Erik Wramner, CodeMint
 */
@WebListener
public class StartupListener implements ServletContextListener {

  @Override
  public void contextInitialized(ServletContextEvent sce) {
    AuthConfigFactory factory = AuthConfigFactory.getFactory();
    factory.registerConfigProvider(new YubiAuthConfigProvider(), "HttpServlet", null, "YubiAuthExample");
  }

  @Override
  public void contextDestroyed(ServletContextEvent sce) {
  }
}