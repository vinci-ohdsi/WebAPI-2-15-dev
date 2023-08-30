package org.ohdsi.webapi.shiro.Entities;

import java.util.List;
import java.util.Set;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

/**
 * Created by GMalikov on 24.08.2015.
 */
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    @Query("SELECT u FROM UserEntity u WHERE lower(u.login) = lower(:login)")
    public UserEntity findByLogin(@Param("login") String login);

    @Query("SELECT u.login FROM UserEntity u")
    public Set<String> getUserLogins();

    @Query("from UserEntity where login = 'testLogin'")
    public UserEntity getTestUser();

    List<UserEntity> findByOrigin(UserOrigin origin);
}
