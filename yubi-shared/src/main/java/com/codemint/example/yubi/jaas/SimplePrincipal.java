package com.codemint.example.yubi.jaas;

import java.security.Principal;

/**
 * Simple principal implementation.
 * 
 * @author Erik Wramner, CodeMint
 */
public class SimplePrincipal implements Principal {
  private final String _name;

  public SimplePrincipal(String name) {
    if (name == null) {
      throw new IllegalArgumentException("Principal name cannot be null");
    }
    _name = name;
  }

  @Override
  public String getName() {
    return _name;
  }

  @Override
  public int hashCode() {
    return _name.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SimplePrincipal other = (SimplePrincipal) obj;
    return _name.equals(other._name);
  }

  @Override
  public String toString() {
    return "SimplePrincipal [_name=" + _name + "]";
  }

}
