package org.ohdsi.webapi.shiro;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.odysseusinc.logging.event.AddUserEvent;
import com.odysseusinc.logging.event.DeleteRoleEvent;

import io.buji.pac4j.subject.Pac4jPrincipal;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.ohdsi.webapi.helper.Guard;
import org.ohdsi.webapi.security.model.UserSimpleAuthorizationInfo;
import org.ohdsi.webapi.shiro.Entities.PermissionEntity;
import org.ohdsi.webapi.shiro.Entities.PermissionRepository;
import org.ohdsi.webapi.shiro.Entities.RequestStatus;
import org.ohdsi.webapi.shiro.Entities.RoleEntity;
import org.ohdsi.webapi.shiro.Entities.RolePermissionEntity;
import org.ohdsi.webapi.shiro.Entities.RolePermissionRepository;
import org.ohdsi.webapi.shiro.Entities.RoleRepository;
import org.ohdsi.webapi.shiro.Entities.UserEntity;
import org.ohdsi.webapi.shiro.Entities.UserOrigin;
import org.ohdsi.webapi.shiro.Entities.UserRepository;
import org.ohdsi.webapi.shiro.Entities.UserRoleEntity;
import org.ohdsi.webapi.shiro.Entities.UserRoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.ohdsi.circe.helper.ResourceHelper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 *
 * @author gennadiy.anisimov
 */
@Component
@Transactional
public class PermissionManager {
  private final Logger logger = LoggerFactory.getLogger(PermissionManager.class);

  @Value("${datasource.ohdsi.schema}")
  private String ohdsiSchema;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;

  @Autowired
  private PermissionRepository permissionRepository;

  @Autowired
  private RolePermissionRepository rolePermissionRepository;

  @Autowired
  private UserRoleRepository userRoleRepository;

  @Autowired
  private ApplicationEventPublisher eventPublisher;
  
  @Autowired
  private JdbcTemplate jdbcTemplate;
  
  private ThreadLocal<ConcurrentHashMap<String, UserSimpleAuthorizationInfo>> authorizationInfoCache = ThreadLocal.withInitial(ConcurrentHashMap::new);

  private Map<AbstractMap.SimpleEntry<String,String>, String> teamProjectRoles = new HashMap<>();

  public static class PermissionsDTO {

    public Map<String, List<String>> permissions = null;
  }
  
  public RoleEntity addRole(String roleName, boolean isSystem) {
    logger.debug("Called addRole: {}", roleName);

    Guard.checkNotEmpty(roleName);

    checkRoleIsAbsent(roleName, isSystem, "Can't create role - it already exists");
    RoleEntity role = new RoleEntity();
    role.setName(roleName);
    role.setSystemRole(isSystem);
    role = this.roleRepository.save(role);

    return role;
  }

  public String addUserToRole(String roleName, String login) {
    return addUserToRole(roleName, login, UserOrigin.SYSTEM);
  }

  public String addUserToRole(String roleName, String login, UserOrigin userOrigin) {
    Guard.checkNotEmpty(roleName);
    Guard.checkNotEmpty(login);

    RoleEntity role = this.getSystemRoleByName(roleName);
    UserEntity user = this.getUserByLogin(login);

    UserRoleEntity userRole = this.addUser(user, role, userOrigin, null);
    return userRole.getStatus();
  }

  public void removeUserFromRole(String roleName, String login, UserOrigin origin) {
    Guard.checkNotEmpty(roleName);
    Guard.checkNotEmpty(login);

    if (roleName.equalsIgnoreCase(login))
      throw new RuntimeException("Can't remove user from personal role");

    RoleEntity role = this.getSystemRoleByName(roleName);
    UserEntity user = this.getUserByLogin(login);

    UserRoleEntity userRole = this.userRoleRepository.findByUserAndRole(user, role);
    if (userRole != null && (origin == null || origin.equals(userRole.getOrigin()))) {
      logger.debug("Removing user from role: {}, {}, {}", user.getLogin(), role.getName(), userRole.getOrigin());
      this.userRoleRepository.delete(userRole);
    }
  }

  public void removeUserFromUserRole(String roleName, String login) {
    Guard.checkNotEmpty(roleName);
    Guard.checkNotEmpty(login);

    if (roleName.equalsIgnoreCase(login))
      throw new RuntimeException("Can't remove user from personal role");

    logger.debug("Checking if role exists: {}", roleName);
    RoleEntity role = this.roleRepository.findByNameAndSystemRole(roleName, false);
    if (role != null) {
      UserEntity user = this.getUserByLogin(login);

      UserRoleEntity userRole = this.userRoleRepository.findByUserAndRole(user, role);
      if (userRole != null) {
        logger.debug("Removing user from USER role: {}, {}", user.getLogin(), roleName);
        this.userRoleRepository.delete(userRole);
      }
    } else {
          logger.debug("Role {} not found", roleName);
    }
  }

  public Iterable<RoleEntity> getRoles(boolean includePersonalRoles) {

    if (includePersonalRoles) {
      return this.roleRepository.findAll();
    } else {
      return this.roleRepository.findAllBySystemRoleTrue();
    }
  }

  /**
   * Return the UserSimpleAuthorizastionInfo which contains the login, roles and permissions for the specified login
   * 
   * @param   login   The login to fetch the authorization info
   * @return          A UserSimpleAuthorizationInfo containing roles and permissions.
  */
  public UserSimpleAuthorizationInfo getAuthorizationInfo(final String login) {

    return authorizationInfoCache.get().computeIfAbsent(login, newLogin -> {
      final UserSimpleAuthorizationInfo info = new UserSimpleAuthorizationInfo();

      final UserEntity userEntity = userRepository.findByLogin(newLogin);
      if(userEntity == null) {
        throw new UnknownAccountException("Account does not exist");
      }

      info.setUserId(userEntity.getId());
      info.setLogin(userEntity.getLogin());

      for (UserRoleEntity userRole: userEntity.getUserRoles()) {
        info.addRole(userRole.getRole().getName());
      }

      // convert permission index from queryUserPermissions() into a map of WildcardPermissions
      Map<String, List<String>> permsIdx = this.queryUserPermissions(newLogin).permissions;
      Map permissionMap = new HashMap<String, List<Permission>>();
      Set<String> permissionNames = new HashSet<>();
      
      for(String permIdxKey : permsIdx.keySet()) {
        List<String> perms = permsIdx.get(permIdxKey);
        permissionNames.addAll(perms);
        // convert raw string permission into Wildcard perm for each element in this key's array.
        permissionMap.put(permIdxKey, perms.stream().map(perm -> new WildcardPermission(perm)).collect(Collectors.toList()));
      }

      info.setStringPermissions(permissionNames);
      info.setPermissionIdx(permissionMap);
      return info;
    });
  }

  public void clearAuthorizationInfoCache() {
    this.authorizationInfoCache.set(new ConcurrentHashMap<>());
  }

  @Transactional
  public void updateUser(String login, Set<String> defaultRoles, Set<String> newUserRoles,
      boolean resetRoles) {
        registerUser(login, null, UserOrigin.SYSTEM, defaultRoles, newUserRoles, resetRoles);
  }

  @Transactional
  public UserEntity registerUser(final String login, final String name, final Set<String> defaultRoles) {
    return registerUser(login, name, UserOrigin.SYSTEM, defaultRoles, null, false);
  }

  @Transactional
  public UserEntity registerUser(final String login, final String name, final UserOrigin userOrigin,
                                 final Set<String> defaultRoles) {
    return registerUser(login, name, userOrigin, defaultRoles, null, false);
  }
  
  @Transactional
  private UserEntity registerUser(final String login, final String name, final UserOrigin userOrigin,
                                 final Set<String> defaultRoles, final Set<String> newUserRoles, boolean resetRoles) {
    logger.debug("Called registerUser with resetRoles: login={}, reset roles={}, default roles={}, new user roles={}",
      login, resetRoles, defaultRoles, newUserRoles);
    Guard.checkNotEmpty(login);
    
    UserEntity user = userRepository.findByLogin(login);
    if (user != null) {
      if (user.getName() == null || !userOrigin.equals(user.getOrigin())) {
        String nameToSet = name;
        if (name == null) {
          nameToSet = login;
        }
        user.setName(nameToSet);
        user.setOrigin(userOrigin);
        user = userRepository.save(user);
      }
      if (resetRoles) {
        // remove all user roles:
        removeAllUserRolesFromUser(login, user, newUserRoles);
        // add back just the given newUserRoles:
        addRolesForUser(login, userOrigin, user, newUserRoles, false);
        // make sure the default roles are there: TODO - discuss if really necessary....
        addDefaultRolesForUser(login, userOrigin, user, defaultRoles);
      }
      // get user again, fresh from db with all new roles:
      user = userRepository.findOne(user.getId());
      return user;  // >>>>>>>>>> RETURN! Add else for readability???
    }

    checkRoleIsAbsent(login, false, "User with such login has been improperly removed from the database. " +
            "Please contact your system administrator");
    user = new UserEntity();
    user.setLogin(login);
    user.setName(name);
    user.setOrigin(userOrigin);
    user = userRepository.save(user);
    eventPublisher.publishEvent(new AddUserEvent(this, user.getId(), login));

    RoleEntity personalRole = this.addRole(login, false);
    this.addUser(user, personalRole, userOrigin, null);
    addRolesForUser(login, userOrigin, user, newUserRoles, false);
    addDefaultRolesForUser(login, userOrigin, user, defaultRoles);
    // get user again, fresh from db with all new roles:
    user = userRepository.findOne(user.getId());
    return user;
  }

  private void addRolesForUser(String login, UserOrigin userOrigin, UserEntity user, Set<String> roles, boolean isSystemRole) {
    if (roles != null) {
      for (String roleName: roles) {
        // Temporary patch/workaround (in reality the role should have been added by sysadmin?):
        if (!isSystemRole) {
          pocAddUserRole(roleName);
        }
        // end temporary patch
        RoleEntity role = this.getRoleByName(roleName, isSystemRole);
        if (role != null) {
          this.addUser(user, role, userOrigin, null);
        }
      }
    }
  }

  private void addDefaultRolesForUser(String login, UserOrigin userOrigin, UserEntity user, Set<String> roles) {
    logger.debug("Adding the following system roles for the user: roles={}", roles);
    addRolesForUser(login, userOrigin, user, roles,true);
  }

  private void removeAllUserRolesFromUser(String login, UserEntity user, final Set<String> rolesToSkip) {
    Set<RoleEntity> userRoles = this.getUserRoles(user);
    // remove all roles except the personal role and any role in the rolesToSkip:
    userRoles.stream().filter(role -> !role.getName().equalsIgnoreCase(login) && !rolesToSkip.contains(role.getName())).forEach(role -> {
        this.removeUserFromUserRole(role.getName(), login);
    });
  }

  private RoleEntity pocAddUserRole(String roleName) {
    RoleEntity role = this.roleRepository.findByNameAndSystemRole(roleName, false);
    if (role != null) {
      return role;
    } else {
      return addRole(roleName, false);
    }
  }

  public Iterable<UserEntity> getUsers() {
    return this.userRepository.findAll();
  }

  public PermissionEntity getOrAddPermission(final String permissionName, final String permissionDescription) {
    Guard.checkNotEmpty(permissionName);

    PermissionEntity permission = this.permissionRepository.findByValueIgnoreCase(permissionName);
    if (permission != null) {
      return permission;
    }

    permission = new PermissionEntity();
    permission.setValue(permissionName);
    permission.setDescription(permissionDescription);
    permission = this.permissionRepository.save(permission);
    return permission;
  }

  public Set<RoleEntity> getUserRoles(Long userId) throws Exception {
    UserEntity user = this.getUserById(userId);
    Set<RoleEntity> roles = this.getUserRoles(user);
    return roles;
  }

  public Iterable<PermissionEntity> getPermissions() {
    return this.permissionRepository.findAll();
  }

  public Set<PermissionEntity> getUserPermissions(Long userId) {
    UserEntity user = this.getUserById(userId);
    Set<PermissionEntity> permissions = this.getUserPermissions(user);
    return permissions;
  }

  public void removeRole(Long roleId) {
    eventPublisher.publishEvent(new DeleteRoleEvent(this, roleId));
    this.roleRepository.delete(roleId);
  }

  public Set<PermissionEntity> getRolePermissions(Long roleId) {
    RoleEntity role = this.getRoleById(roleId);
    Set<PermissionEntity> permissions = this.getRolePermissions(role);
    return permissions;
  }

  public void addPermission(Long roleId, Long permissionId) {
    PermissionEntity permission = this.getPermissionById(permissionId);
    RoleEntity role = this.getRoleById(roleId);

    this.addPermission(role, permission, null);
  }

  public void addPermission(RoleEntity role, PermissionEntity permission) {
    this.addPermission(role, permission, null);
  }

  public void removePermission(Long permissionId, Long roleId) {
    RolePermissionEntity rolePermission = this.rolePermissionRepository.findByRoleIdAndPermissionId(roleId, permissionId);
    if (rolePermission != null)
      this.rolePermissionRepository.delete(rolePermission);
  }

  public Set<UserEntity> getRoleUsers(Long roleId) {
    RoleEntity role = this.getRoleById(roleId);
    Set<UserEntity> users = this.getRoleUsers(role);
    return users;
  }

  public void addUser(Long userId, Long roleId) {
    UserEntity user = this.getUserById(userId);
    RoleEntity role = this.getRoleById(roleId);

    this.addUser(user, role, UserOrigin.SYSTEM, null);
  }

  public void removeUser(Long userId, Long roleId) {
    UserRoleEntity userRole = this.userRoleRepository.findByUserIdAndRoleId(userId, roleId);
    if (userRole != null)
      this.userRoleRepository.delete(userRole);
  }

  public void removePermission(String value) {
    PermissionEntity permission = this.permissionRepository.findByValueIgnoreCase(value);
    if (permission != null)
      this.permissionRepository.delete(permission);
  }

  public RoleEntity getUserPersonalRole(String username) {

    return this.getRoleByName(username, false);
  }

  public RoleEntity getCurrentUserPersonalRole() {
    String username = this.getSubjectName();
    return getUserPersonalRole(username);
  }
  private void checkRoleIsAbsent(String roleName, boolean isSystem, String message) {
    RoleEntity role = this.roleRepository.findByNameAndSystemRole(roleName, isSystem);
    if (role != null) {
      throw new RuntimeException(message);
    }
  }


  public Set<PermissionEntity> getUserPermissions(UserEntity user) {
    Set<RoleEntity> roles = this.getUserRoles(user);
    Set<PermissionEntity> permissions = new LinkedHashSet<>();

    for (RoleEntity role : roles) {
      permissions.addAll(this.getRolePermissions(role));
    }

    return permissions;
  }
  
  public PermissionsDTO queryUserPermissions(final String login) {
    String permQuery = StringUtils.replace(
            ResourceHelper.GetResourceAsString("/resources/security/getPermissionsForUser.sql"),
            "@ohdsi_schema",
            this.ohdsiSchema);
    final UserEntity user = userRepository.findByLogin(login);

    List<String> permissions = this.jdbcTemplate.query(
            permQuery, 
            (ps) -> {
              ps.setLong(1, user.getId());
            },
            (rs, rowNum) -> {
              return rs.getString("value");
            });
    PermissionsDTO permDto = new PermissionsDTO();
    permDto.permissions = permsToMap(permissions);
    return permDto;
  }

  /**
   * This method takes a list of strings and returns a JSObject representing 
   * the first element of each permission as a key, and the List<String> of 
   * permissions that start with the key as the value
  */
  private Map<String, List<String>> permsToMap(List<String> permissions) {

    Map<String, List<String>> resultMap = new HashMap<>();

    // Process each input string
    for (String inputString : permissions) {
      String[] parts = inputString.split(":");
      String key = parts[0];
      // Create a new JsonArray for the key if it doesn't exist
      resultMap.putIfAbsent(key, new ArrayList<>());
      // Add the value to the JsonArray
      resultMap.get(key).add(inputString);
    }

    // Convert the resultMap to a JsonNode

    return resultMap;
  }
  
  private Set<PermissionEntity> getRolePermissions(RoleEntity role) {
    Set<PermissionEntity> permissions = new LinkedHashSet<>();

    Set<RolePermissionEntity> rolePermissions = role.getRolePermissions();
    for (RolePermissionEntity rolePermission : rolePermissions) {
      if (isRelationAllowed(rolePermission.getStatus())) {
        PermissionEntity permission = rolePermission.getPermission();
        permissions.add(permission);
      }
    }

    return permissions;
  }

  private Set<RoleEntity> getUserRoles(UserEntity user) {
    Set<UserRoleEntity> userRoles = user.getUserRoles();
    logger.debug("Called getUserRoles. Found: {}", userRoles);
    Set<RoleEntity> roles = new LinkedHashSet<>();
    for (UserRoleEntity userRole : userRoles) {
      if (isRelationAllowed(userRole.getStatus())) {
        RoleEntity role = userRole.getRole();
        roles.add(role);
      }
    }

    return roles;
  }

  private Set<UserEntity> getRoleUsers(RoleEntity role) {
    Set<UserEntity> users = new LinkedHashSet<>();
    for (UserRoleEntity userRole : role.getUserRoles()) {
      if (isRelationAllowed(userRole.getStatus())) {
        users.add(userRole.getUser());
      }
    }
    return users;
  }

  public UserEntity getCurrentUser() {
    final String login = this.getSubjectName();
    final UserEntity currentUser = this.getUserByLogin(login);
    return currentUser;
  }

  public UserEntity getUserById(Long userId) {
    UserEntity user = this.userRepository.findOne(userId);
    if (user == null)
      throw new RuntimeException("User doesn't exist");

    return user;
  }

  private UserEntity getUserByLogin(final String login) {
    logger.debug("Looking for user login={}...", login);
    final UserEntity user = this.userRepository.findByLogin(login);
    if (user == null) {
      logger.error("User does NOT exist for login={}...", login);
      throw new RuntimeException("User doesn't exist");
    }
    return user;
  }

  private RoleEntity getRoleByName(String roleName, Boolean isSystemRole) {
    final RoleEntity roleEntity = this.roleRepository.findByNameAndSystemRole(roleName, isSystemRole);
    if (roleEntity == null)
      throw new RuntimeException("Role doesn't exist:" + roleName);

    return roleEntity;
  }

  public RoleEntity getSystemRoleByName(String roleName) {
    return getRoleByName(roleName, true);
  }

  private RoleEntity getRoleById(Long roleId) {
    final RoleEntity roleEntity = this.roleRepository.findById(roleId);
    if (roleEntity == null)
      throw new RuntimeException("Role doesn't exist:" + roleId);

    return roleEntity;
  }

  private PermissionEntity getPermissionById(Long permissionId) {
    final PermissionEntity permission = this.permissionRepository.findById(permissionId);
    if (permission == null )
      throw new RuntimeException("Permission doesn't exist");

    return permission;
  }

  private RolePermissionEntity addPermission(final RoleEntity role, final PermissionEntity permission, final String status) {
    RolePermissionEntity relation = this.rolePermissionRepository.findByRoleAndPermission(role, permission);
    if (relation == null) {
      relation = new RolePermissionEntity();
      relation.setRole(role);
      relation.setPermission(permission);
      relation.setStatus(status);
      relation = this.rolePermissionRepository.save(relation);
    }

    return relation;
  }

  private boolean isRelationAllowed(final String relationStatus) {
    return relationStatus == null || relationStatus.equals(RequestStatus.APPROVED);
  }

  private UserRoleEntity addUser(final UserEntity user, final RoleEntity role,
                                 final UserOrigin userOrigin, final String status) {
    UserRoleEntity relation = this.userRoleRepository.findByUserAndRole(user, role);
    if (relation == null) {
      logger.debug("The role={} is new for this user. Adding...", role.getName());
      relation = new UserRoleEntity();
      relation.setUser(user);
      relation.setRole(role);
      relation.setStatus(status);
      relation.setOrigin(userOrigin);
      relation = this.userRoleRepository.save(relation);
    } else {
        logger.debug("The user already had the role={}", role.getName());
    }

    return relation;
  }

  public String getSubjectName() {
    Subject subject = SecurityUtils.getSubject();
    Object principalObject = subject.getPrincipals().getPrimaryPrincipal();

    if (principalObject instanceof String) {
      logger.debug("principal IS STRING: " + principalObject);
      return (String)principalObject;
    }

    if (principalObject instanceof Pac4jPrincipal) {
      String login = ((Pac4jPrincipal)principalObject).getProfile().getEmail();
      logger.debug("principal IS Pac4jPrincipal: " + login);
      return login;
    }

    if (principalObject instanceof Principal) {
      Principal principal = (Principal)principalObject;
      logger.debug("principal IS Principal: " + principal.getName());
      return principal.getName();
    }

    throw new UnsupportedOperationException();
  }

  public RoleEntity getRole(Long id) {
    return this.roleRepository.findById(id);
  }

  public RoleEntity updateRole(RoleEntity roleEntity) {
    return this.roleRepository.save(roleEntity);
  }

  public void addPermissionsFromTemplate(RoleEntity roleEntity, Map<String, String> template, String value) {
    for (Map.Entry<String, String> entry : template.entrySet()) {
      String permission = String.format(entry.getKey(), value);
      String description = String.format(entry.getValue(), value);
      PermissionEntity permissionEntity = this.getOrAddPermission(permission, description);
      this.addPermission(roleEntity, permissionEntity);
    }
  }

  public void addPermissionsFromTemplate(Map<String, String> template, String value) {
    RoleEntity currentUserPersonalRole = getCurrentUserPersonalRole();
    addPermissionsFromTemplate(currentUserPersonalRole, template, value);
  }

  public void removePermissionsFromTemplate(Map<String, String> template, String value) {
    for (Map.Entry<String, String> entry : template.entrySet()) {
      String permission = String.format(entry.getKey(), value);
      this.removePermission(permission);
    }
  }

  public boolean roleExists(String roleName) {
    return this.roleRepository.existsByName(roleName);
  }

  private String getCurrentUserSessionId() {
    Subject subject = SecurityUtils.getSubject();
    return subject.getSession(false).getId().toString();
  }

  private AbstractMap.SimpleEntry<String,String> getCurrentUserAndSessionTuple() {
    AbstractMap.SimpleEntry<String, String> userAndSessionTuple = new AbstractMap.SimpleEntry<>
      (getCurrentUser().getLogin(), getCurrentUserSessionId());
    return userAndSessionTuple;
  }

  public void setCurrentTeamProjectRoleForCurrentUser(String teamProjectRole, String login) {
    logger.debug("Current user in setCurrentTeamProjectRoleForCurrentUser() {}", login);
    this.teamProjectRoles.put(getCurrentUserAndSessionTuple(), teamProjectRole);
  }

  public RoleEntity getCurrentTeamProjectRoleForCurrentUser() {
    logger.debug("Current user in getCurrentTeamProjectRoleForCurrentUser(): {}", getCurrentUser().getLogin());
    String teamProjectRole = this.teamProjectRoles.get(getCurrentUserAndSessionTuple());
    if (teamProjectRole == null) {
      return null;
    } else {
      return this.getRoleByName(teamProjectRole, false);
    }
  }
}
