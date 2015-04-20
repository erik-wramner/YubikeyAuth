package com.codemint.example.yubi.data;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class represents a user account with a hashed password and roles. It is
 * built for demo purposes only and can read and write itself to plain text
 * files. It is NOT intended for production use.
 * 
 * @author Erik Wramner, CodeMint
 */
public class UserAccount implements Comparable<UserAccount> {
  private final String _email;
  private final String _hashedPassword;
  private final String _publicYubiId;
  private final int _salt;
  private final Set<String> _roles;

  /**
   * Constructor.
   * 
   * @param email
   *          The e-mail/account id.
   * @param hashedPassword
   *          The hashed password.
   * @param publicYubiId
   *          The public Yubikey id.
   * @param salt
   *          The random salt for this user.
   */
  public UserAccount(String email, String hashedPassword, String publicYubiId, int salt) {
    _email = email;
    _hashedPassword = hashedPassword;
    _publicYubiId = publicYubiId;
    _salt = salt;
    _roles = new HashSet<>();
  }

  public String getEmail() {
    return _email;
  }

  public String getHashedPassword() {
    return _hashedPassword;
  }

  public String getPublicYubiId() {
    return _publicYubiId;
  }

  public int getSalt() {
    return _salt;
  }

  public Set<String> getRoles() {
    return Collections.unmodifiableSet(_roles);
  }

  public void addRole(String role) {
    _roles.add(role);
  }

  public void removeRole(String role) {
    _roles.remove(role);
  }

  @Override
  public int hashCode() {
    return _email.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    UserAccount other = (UserAccount) obj;
    if (_email == null) {
      if (other._email != null)
        return false;
    } else if (!_email.equals(other._email))
      return false;
    return true;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("UserAccount [_email=");
    builder.append(_email);
    builder.append(", _roles=");
    builder.append(_roles);
    builder.append("]");
    return builder.toString();
  }

  @Override
  public int compareTo(UserAccount other) {
    return getEmail().compareTo(other.getEmail());
  }

  public static Set<UserAccount> readAccounts(File file) throws IOException {
    Set<UserAccount> accounts = new HashSet<>();
    try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
      for (String line = reader.readLine(); line != null; line = reader.readLine()) {
        String trimmedLine = line.trim();
        if (!trimmedLine.isEmpty()) {
          String[] fields = trimmedLine.split(";");
          UserAccount account = new UserAccount(fields[0], fields[1], fields[2], Integer.parseInt(fields[3]));
          if (fields.length > 4) {
            String[] roles = fields[4].split("\\|");
            for (String role : roles) {
              if (role != null && !role.trim().isEmpty()) {
                account.addRole(role);
              }
            }
          }
          accounts.add(account);
        }
      }
    }
    return accounts;
  }

  public static void writeAccounts(Set<UserAccount> accounts, File file) throws IOException {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
      for (UserAccount account : accounts) {
        writer.append(account.getEmail());
        writer.append(';');
        writer.append(account.getHashedPassword());
        writer.append(';');
        writer.append(account.getPublicYubiId());
        writer.append(';');
        writer.append(String.valueOf(account.getSalt()));
        writer.append(';');
        for (String role : account.getRoles()) {
          writer.append(role);
          writer.append('|');
        }
        writer.append(';');
      }
      writer.flush();
    }
  }

  /**
   * Create a map from user identities to user accounts based on a text file.
   * 
   * @param path
   *          The path to the user account file.
   * @return map with all accounts.
   */
  public static Map<String, UserAccount> createAccountMap(String path) {
    Map<String, UserAccount> map = new HashMap<>();
    try {
      for (UserAccount account : UserAccount.readAccounts(new File(path))) {
        map.put(account.getEmail(), account);
      }
      return map;
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read accounts", e);
    }
  }
}
