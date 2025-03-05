package com.example.securitySpringboots.Repository;

import com.example.securitySpringboots.Entity.Role;
import com.example.securitySpringboots.models.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
