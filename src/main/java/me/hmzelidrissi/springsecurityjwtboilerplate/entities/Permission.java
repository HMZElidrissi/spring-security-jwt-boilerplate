package me.hmzelidrissi.springsecurityjwtboilerplate.entities;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
// enums in java are classes that inherit from java.lang.Enum, this class is final so we can't extend it, and we can't extend any other class as well
public enum Permission {
    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_DELETE("admin:delete"),
    ADMIN_CREATE("admin:create"),
    MANAGER_READ("manager:read"),
    MANAGER_UPDATE("manager:update"),
    MANAGER_DELETE("manager:delete"),
    MANAGER_CREATE("manager:create"),
    ;

    @Getter
    private final String permission;
}
