package org.ohdsi.webapi.shiro.realms;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.ohdsi.webapi.shiro.PermissionManager;
import org.ohdsi.webapi.shiro.tokens.JwtAuthToken;

import io.buji.pac4j.subject.Pac4jPrincipal;

/**
 *
 * @author gennadiy.anisimov
 */
public class JwtAuthRealm extends AuthorizingRealm {
  
  private final PermissionManager authorizer;

  public JwtAuthRealm(PermissionManager authorizer) {
    this.authorizer = authorizer;
  }

  @Override
  public boolean supports(AuthenticationToken token) {

    return token != null && token.getClass() == JwtAuthToken.class;
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    String login;
    Object principal = principals.getPrimaryPrincipal();
    if (principal instanceof Pac4jPrincipal) {
      login = ((Pac4jPrincipal)principal).getProfile().getEmail();
    }
    else {
      login = (String) principals.getPrimaryPrincipal();
    }
    return authorizer.getAuthorizationInfo(login);
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken at) throws AuthenticationException {
    return new SimpleAuthenticationInfo(at.getPrincipal(), "", getName());
  }  
}
