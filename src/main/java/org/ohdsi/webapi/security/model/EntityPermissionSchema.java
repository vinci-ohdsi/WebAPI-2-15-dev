package org.ohdsi.webapi.security.model;

import org.ohdsi.webapi.model.CommonEntity;
import org.ohdsi.webapi.shiro.Entities.RoleEntity;
import org.ohdsi.webapi.shiro.filters.UpdateAccessTokenFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ohdsi.webapi.shiro.PermissionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class EntityPermissionSchema {
    private final Logger logger = LoggerFactory.getLogger(UpdateAccessTokenFilter.class);

    private final EntityType entityType;
    private final Map<String, String> readPermissions;
    private final Map<String, String> writePermissions;

    @Value("${security.ohdsi.custom.authorization.mode}")
    private String authorizationMode;

    @Autowired
    protected PermissionManager permissionManager;

    public EntityPermissionSchema(EntityType entityType, Map<String, String> readPermissions, Map<String, String> writePermissions) {

        this.entityType = entityType;
        this.readPermissions = readPermissions;
        this.writePermissions = Collections.unmodifiableMap(writePermissions);
    }

    public EntityType getEntityType() {

        return entityType;
    }

    public Map<String, String> getReadPermissions() {

        return readPermissions;
    }

    public Map<String, String> getWritePermissions() {

        return writePermissions;
    }

    public Map<String, String> getAllPermissions() {

        Map<String, String> permissions = new HashMap<>();
        permissions.putAll(getReadPermissions());
        permissions.putAll(getWritePermissions());
        return permissions;
    }

    public void onInsert(CommonEntity commonEntity) {
        logger.debug("AUTHORIZATION_MODE in EntityPermissionSchema == '{}'", this.authorizationMode);
        if (this.authorizationMode.equals("teamproject")) {
            addPermissionsToCurrentTeamProjectFromTemplate(commonEntity, getAllPermissions());
        } else {
            addPermissionsToCurrentUserFromTemplate(commonEntity, getAllPermissions());
        }
    }

    public void onDelete(CommonEntity commonEntity) {

        Map<String, String> permissionTemplates = getAllPermissions();
        permissionManager.removePermissionsFromTemplate(permissionTemplates, commonEntity.getId().toString());
    }

    protected void addPermissionsToCurrentUserFromTemplate(CommonEntity commonEntity, Map<String, String> template) {

        String login = permissionManager.getSubjectName();
        RoleEntity role = permissionManager.getUserPersonalRole(login);
        permissionManager.addPermissionsFromTemplate(role, template, commonEntity.getId().toString());
    }

    protected void addPermissionsToCurrentTeamProjectFromTemplate(CommonEntity commonEntity, Map<String, String> template) {

        RoleEntity role = permissionManager.getCurrentTeamProjectRoleForCurrentUser();
        if (role == null) {
            throw new RuntimeException("Expected a teamproject role but found none!");
        }
        permissionManager.addPermissionsFromTemplate(role, template, commonEntity.getId().toString());
    }
}
