package com.zhouij.authplatform.authserver.auth

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class IamLoginAuthenticationToken(
    principal: Any,
    credentials: Any,
    val userType: String,
    authorities: Collection<GrantedAuthority> = emptySet()
) : UsernamePasswordAuthenticationToken(principal, credentials, authorities) {

    companion object {
        fun unauthenticated(email: String, password: String, userType: String): IamLoginAuthenticationToken {
            return IamLoginAuthenticationToken(email, password, userType)
        }

        fun authenticated(
            principal: IamPrincipal,
            credentials: Any,
            authorities: Collection<GrantedAuthority>
        ): IamLoginAuthenticationToken {
            val token = IamLoginAuthenticationToken(principal, credentials, principal.userType, authorities)
            token.isAuthenticated = true
            return token
        }
    }

    val email: String
        get() = (principal as? String) ?: (principal as? IamPrincipal)?.email ?: ""

    val selectedUserType: String
        get() = (principal as? IamPrincipal)?.userType ?: userType
}
