package org.ohdsi.webapi.shiro.filters;

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.ohdsi.webapi.shiro.PermissionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author Pieter Lukasse
 */
public class TeamProjectBasedAuthorizingFilter extends AdviceFilter {

  private final Logger logger = LoggerFactory.getLogger(TeamProjectBasedAuthorizingFilter.class);

  private final PermissionManager authorizer;
  private final Set<String> defaultRoles;
  private final String authorizationMode;
  private final String authorizationUrl;

  public TeamProjectBasedAuthorizingFilter(
          PermissionManager authorizer,
          Set<String> defaultRoles,
          String authorizationMode,
          String authorizationUrl) {
    this.authorizer = authorizer;
    this.defaultRoles = defaultRoles;
    this.authorizationMode = authorizationMode;
    this.authorizationUrl = authorizationUrl;
    logger.debug("AUTHORIZATION_MODE in TeamProjectBasedAuthorizingFilter constructor == '{}'", this.authorizationMode);
    logger.debug("AUTHORIZATION_URL in TeamProjectBasedAuthorizingFilter constructor == '{}'", this.authorizationUrl);
  }

  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

    try {
        logger.debug("preHandle in TeamProjectBasedAuthorizingFilter == '{}'", this.authorizationMode);
        boolean resetRoles = false;
        String teamProjectRole = null;
        Set<String> newUserRoles = new HashSet<String>();
        Set<String> newDefaultRoles = new HashSet<String>(defaultRoles);
        if (this.authorizationMode.equals("teamproject") && SecurityUtils.getSubject().isAuthenticated()) {
          // in case of "teamproject" mode, we want all roles to be reset always, and
          // set to only the one requested/found in the request parameters (following lines below):
          resetRoles = true;
          // check if a teamproject parameter is found in the request:
          teamProjectRole = extractTeamProjectFromRequestParameters(request);
          // if found, and teamproject is different from current one, add teamproject as a role in the newUserRoles list:
          if (teamProjectRole != null &&
              (this.authorizer.getCurrentTeamProjectRoleForCurrentUser() == null || !teamProjectRole.equals(this.authorizer.getCurrentTeamProjectRoleForCurrentUser().getName()))) {
            // double check if this role has really been granted to the user:
            String login = this.authorizer.getCurrentUser().getLogin();
            if (checkGen3Authorization(teamProjectRole, login) == false) {
              WebUtils.toHttp(response).sendError(HttpServletResponse.SC_FORBIDDEN,
               "User is not authorized to access this team project's data");
              return false;
            }
            newUserRoles.add(teamProjectRole);
            newDefaultRoles.add("Atlas users"); // TODO - review this part...maybe users can get this role when onboarding (system role?)
            this.authorizer.updateUser(login, newDefaultRoles, newUserRoles, resetRoles);
            this.authorizer.setCurrentTeamProjectRoleForCurrentUser(teamProjectRole, login);
          }
        }

      } catch (Exception e) {
        WebUtils.toHttp(response).setHeader("x-auth-error", e.getMessage());
        throw new Exception(e);
      }

    return true;
  }

  private boolean checkGen3Authorization(String teamProjectRole, String login) throws Exception {
    logger.debug("Checking Gen3 Authorization for 'team project'={} and user={} using service={}", teamProjectRole, login, this.authorizationUrl);
    RestTemplate restTemplate = new RestTemplate();
    String arboristAuthorizationURL = this.authorizationUrl;
    String requestBody = String.format("{\"username\": \"%s\"}", login);
    String jsonResponseString = restTemplate.postForObject(arboristAuthorizationURL, requestBody, String.class);

    JSONObject jsonObject = new JSONObject(jsonResponseString);

    if (!jsonObject.keySet().contains(teamProjectRole)) {
      logger.warn("User is not authorized to access this team project's data");
      return false;
    } else {
      JSONArray teamProjectAuthorizations = jsonObject.getJSONArray(teamProjectRole);
      logger.debug("Found authorizations={}", teamProjectAuthorizations);
      // We expect only one authorization rule per teamproject:
      if (teamProjectAuthorizations.length() != 1) {
        logger.error("Only one authorization rule expected for 'teamproject'={}, found={}", teamProjectRole,
          teamProjectAuthorizations.length());
        return false;
      }
      JSONObject teamProjectAuthorization = teamProjectAuthorizations.getJSONObject(0);

      // check if the authorization contains the right "service" and "method" values:
      String expectedMethod = "access";
      String expectedService = "atlas-argo-wrapper-and-cohort-middleware"; // TODO - make the service name configurable?
      String service = teamProjectAuthorization.getString("service");
      String method = teamProjectAuthorization.getString("method");
      logger.debug("Parsed service={} and method={}", service, method);
      if (!method.equalsIgnoreCase(expectedMethod)) {
        logger.error("The 'teamproject' authorization method should be '{}', but found '{}'", expectedMethod, method);
        return false;
      }
      logger.debug("Parsed method is as expected");
      if (!service.equalsIgnoreCase(expectedService)) {
        logger.error("The 'teamproject' authorization service should be '{}', but found '{}'", expectedService, service);
        return false;
      }
      logger.debug("Parsed service is as expected");
      return true;
    }
  }

  private String extractTeamProjectFromRequestParameters(ServletRequest request) {
    // Get the url
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String url = httpRequest.getRequestURL().toString();

    // try to find it in the redirectUrl parameter:
    logger.debug("Looking for redirectUrl in request: {}....", url);
    String[] redirectUrlParams = getParameterValues(request, "redirectUrl");
    if (redirectUrlParams != null) {
      logger.debug("Parameter redirectUrl found. Checking if it contains teamproject....");
      // teamProject will be in first one in this case...as only parameter:
      String firstParameter = redirectUrlParams[0].toLowerCase();
      if (firstParameter.contains("teamproject=")) {
        String teamProject = firstParameter.split("teamproject=")[1];
        logger.debug("Found teamproject: {}", teamProject);
        return teamProject;
      }
    }

    // try to find "teamproject" param in url itself (there will be no redirectUrl if user session is still valid):
    logger.debug("Fallback1: Looking for teamproject in request: {}....", url);
    String[] teamProjectParams = getParameterValues(request, "teamproject");
    if (teamProjectParams != null) {
      logger.debug("Parameter teamproject found. Parsing....");
      String teamProject = teamProjectParams[0].toLowerCase();
      logger.debug("Found teamproject: {}", teamProject);
      return teamProject;
    }

    logger.debug("Fallback2: Looking for teamproject in Action-Location header of request: {}....", url);
    String actionLocationUrl = httpRequest.getHeader("Action-Location");
    if (actionLocationUrl != null && actionLocationUrl.contains("teamproject=")) {
      String teamProject = actionLocationUrl.split("teamproject=")[1];
      logger.debug("Found teamproject: {}", teamProject);
      return teamProject;
    }

    logger.debug("Found NO teamproject.");
    return null;
  }

  private String[] getParameterValues(ServletRequest request, String parameterName) {
    // Get the parameters
    logger.debug("Looking for parameter with name: {} ...", parameterName);
    Enumeration<String> paramNames = request.getParameterNames();
    while(paramNames.hasMoreElements()) {
        String paramName = paramNames.nextElement();
        logger.debug("Parameter name: {}", paramName);
        if (paramName.equals(parameterName)) {
          String[] paramValues = request.getParameterValues(paramName);
          return paramValues;
        }
    }
    logger.debug("Found NO parameter with name: {}", parameterName);
    return null;
  }

}
