package com.security.jwtredefined.entity;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public enum Role {
    USER,
    ADMIN,
    MANAGER,
    SUPER_ADMIN;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        //Collection<? extends GrantedAuthority> Role = null;
        return null;
    }
}

