package com.codemint.example.yubi.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple password encoder that computes one-way hashes for passwords.
 * <p>
 * The implementation uses SHA-256 with multiple passes (each using user id and
 * salt) in order to withstand attacks.
 * 
 * @author Erik Wramner, CodeMint
 */
public class PasswordEncoder {
  private static final String UTF_8 = "UTF-8";
  private static final int NUM_PASSES = 25;

  /**
   * Encode a password for a specific user with a one-way hash.
   * 
   * @param userId
   *          The user id.
   * @param salt
   *          The random salt for the user.
   * @param password
   *          The password.
   * @return hashed password.
   */
  public static String encodePasswordForUser(String userId, int salt, String password) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] userIdBytes = userId.getBytes(UTF_8);
      final byte[] saltBytes = String.valueOf(salt).getBytes(UTF_8);
      byte[] bytes = password.getBytes(UTF_8);
      for (int i = 0; i < NUM_PASSES; i++) {
        digest.update(userIdBytes);
        digest.update(saltBytes);
        digest.update(bytes);
        bytes = digest.digest();
      }
      return String.format("%X", new BigInteger(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Required algorithm SHA-256 missing in JVM!");
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException("Required encoding " + UTF_8 + " missing in JVM!");
    }
  }
}
