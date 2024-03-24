package com.security.jwtredefined.Repo;


import com.security.jwtredefined.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<UserRole,Long> {
    UserRole findByName(String name);
}