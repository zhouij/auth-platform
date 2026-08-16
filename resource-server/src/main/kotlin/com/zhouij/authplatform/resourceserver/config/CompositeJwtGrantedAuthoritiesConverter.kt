package com.zhouij.authplatform.resourceserver.config

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt

class CompositeJwtGrantedAuthoritiesConverter : Converter<Jwt, Collection<GrantedAuthority>> {

    override fun convert(jwt: Jwt): Collection<GrantedAuthority> {
        val authorities = mutableSetOf<GrantedAuthority>()

        // OAuth2 scopes -> SCOPE_read, SCOPE_write
        // The scope claim may be a space-delimited String or (as issued by
        // Spring Authorization Server 7) a JSON array of strings.
        val scopeClaim = jwt.claims["scope"]
        val scopes = when (scopeClaim) {
            is String -> scopeClaim
            is Collection<*> -> scopeClaim.filterIsInstance<String>().joinToString(" ")
            else -> null
        }
        if (scopes != null) {
            scopes.split(" ").mapTo(authorities) { SimpleGrantedAuthority("SCOPE_$it") }
        }

        // Custom "roles" claim -> ROLE_ADMIN, ROLE_ADMIN_GROUP_*
        @Suppress("UNCHECKED_CAST")
        val roles = jwt.claims["roles"] as? List<String>
        roles?.forEach { role ->
            authorities.add(SimpleGrantedAuthority("ROLE_$role"))
        }

        // Ensure ADMIN user_type always has base ROLE_ADMIN
        val userType = jwt.claims["user_type"] as? String
        if (userType == "ADMIN" && authorities.none { it.authority == "ROLE_ADMIN" }) {
            authorities.add(SimpleGrantedAuthority("ROLE_ADMIN"))
        }

        return authorities
    }
}
