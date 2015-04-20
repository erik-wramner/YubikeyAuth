package com.codemint.example.yubi.data;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import com.codemint.example.yubi.util.PasswordEncoder;

/**
 * This class generates a file with user accounts for test purposes.
 * 
 * @author Erik Wramner, CodeMint
 */
public class UserAccountGenerator {
  private static final String[][] TEST_ACCOUNTS = new String[][] { new String[] { "erik.wramner@codemint.com", "test",
      "ccccccdudunk", "Users" } };

  public static void main(String[] args) throws IOException {
    if (args.length != 1) {
      System.out.println("Usage: java " + UserAccountGenerator.class.getName() + " <file>");
      System.exit(0);
    }
    Random random = new SecureRandom();
    Set<UserAccount> accounts = new TreeSet<>();
    for (String[] testAccountData : TEST_ACCOUNTS) {
      final int userSalt = random.nextInt();
      UserAccount account = new UserAccount(testAccountData[0], PasswordEncoder.encodePasswordForUser(
          testAccountData[0], userSalt, testAccountData[1]), testAccountData[2], userSalt);
      for (int i = 3; i < testAccountData.length; i++) {
        account.addRole(testAccountData[i]);
      }
      accounts.add(account);
    }
    File file = new File(args[0]);
    UserAccount.writeAccounts(accounts, file);
    accounts = UserAccount.readAccounts(file);
    System.out.println("Accounts: " + accounts);
  }

}
