package com.zhouij.authplatform.iam.config

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt

/**
 * Maps OAuth2 scopes to SCOPE_* authorities and the custom "roles" claim to
 * ROLE_* authorities. The default converter only handles scopes, which made
 * the admin endpoints (hasRole checks) unreachable.
 */
class JwtRolesGrantedAuthoritiesConverter : Converter<Jwt, Collection<GrantedAuthority>> {

    override fun convert(jwt: Jwt): Collection<GrantedAuthority> {
        val authorities = mutableSetOf<GrantedAuthority>()

        val scopeClaim = jwt.claims["scope"]
        val scopes = when (scopeClaim) {
            is String -> scopeClaim
            is Collection<*> -> scopeClaim.filterIsInstance<String>().joinToString(" ")
            else -> null
        }
        scopes?.split(" ")?.mapTo(authorities) { SimpleGrantedAuthority("SCOPE_$it") }

        @Suppress("UNCHECKED_CAST")
        val roles = jwt.claims["roles"] as? List<String>
        roles?.forEach { authorities.add(SimpleGrantedAuthority("ROLE_$it")) }

        if (jwt.claims["user_type"] == "ADMIN" && authorities.none { it.authority == "ROLE_ADMIN" }) {
            authorities.add(SimpleGrantedAuthority("ROLE_ADMIN"))
        }

        return authorities
    }
}
