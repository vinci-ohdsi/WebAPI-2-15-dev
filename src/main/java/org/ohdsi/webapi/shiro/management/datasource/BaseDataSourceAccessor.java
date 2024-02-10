package org.ohdsi.webapi.shiro.management.datasource;

import org.apache.shiro.SecurityUtils;
import org.ohdsi.webapi.shiro.management.DisabledSecurity;
import org.ohdsi.webapi.shiro.management.Security;
import org.ohdsi.webapi.source.Source;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.ForbiddenException;

public abstract class BaseDataSourceAccessor<T> implements DataSourceAccessor<T> {

  private final Logger logger = LoggerFactory.getLogger(BaseDataSourceAccessor.class);

  @Autowired(required = false)
  private DisabledSecurity disabledSecurity;

  public void checkAccess(T s) {
    if (!hasAccess(s)) {
      throw new ForbiddenException();
    }
  }

  public boolean hasAccess(T s) {
    if (disabledSecurity != null) {
      return true;
    }

    Source source = extractSource(s);
    if (source == null) {
      logger.debug("Found extractSource() to return null!");
      return false;
    }

    boolean isPermitted = SecurityUtils.getSubject().isPermitted(String.format(Security.SOURCE_ACCESS_PERMISSION, source.getSourceKey()));
    logger.debug("Returning isPermitted={} for {}", isPermitted, String.format(Security.SOURCE_ACCESS_PERMISSION, source.getSourceKey()));
    return isPermitted;
  }

  protected abstract Source extractSource(T source);

}
