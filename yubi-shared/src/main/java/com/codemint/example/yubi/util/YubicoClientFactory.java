package com.codemint.example.yubi.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import com.yubico.client.v2.YubicoClient;

/**
 * Factory that creates {@link YubicoClient} instances with key and client id
 * from a property file. Visit <a
 * href="https://upgrade.yubico.com/getapikey">Yubico</a> to get your own key.
 * 
 * @author Erik Wramner, CodeMint
 */
public class YubicoClientFactory {
  private static final YubicoClientFactory INSTANCE = new YubicoClientFactory();
  private final Properties _yubicoProperties = loadYubicoProperties();

  /**
   * Get a client.
   * 
   * @return client.
   */
  public static YubicoClient getYubicoClient() {
    return INSTANCE.createYubicoClient();
  }

  private YubicoClient createYubicoClient() {
    return YubicoClient.getClient(Integer.valueOf(_yubicoProperties.getProperty("client_id")),
        _yubicoProperties.getProperty("secret_key"));
  }

  private static Properties loadYubicoProperties() {
    InputStream is = null;
    try {
      is = YubicoClientFactory.class.getResourceAsStream("/yubico.properties");
      if (is != null) {
        Properties props = new Properties();
        props.load(is);
        return props;
      } else {
        throw new IllegalStateException("Failed to read yubico.properties!");
      }
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read yubico.properties!", e);
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
