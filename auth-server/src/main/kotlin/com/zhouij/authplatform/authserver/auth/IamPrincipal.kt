package com.zhouij.authplatform.authserver.auth

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

data class IamPrincipal(
    val userId: String,
    val email: String,
    val username: String,
    val firstName: String,
    val lastName: String,
    val userType: String,
    val enabled: Boolean,
    val authorities: Collection<GrantedAuthority>
) : java.security.Principal, java.io.Serializable {

    // Used by Authentication.getName() and therefore as the oauth2_authorization
    // principal_name (max 200 chars) and the default JWT "sub" claim.
    override fun getName(): String = userId

    companion object {
        fun fromResponse(data: Map<String, Any>): IamPrincipal {
            val authorities = (data["authorities"] as? List<*>)?.map {
                SimpleGrantedAuthority(it.toString())
            } ?: emptyList()

            return IamPrincipal(
                userId = data["userId"] as? String ?: "",
                email = data["email"] as? String ?: "",
                username = data["username"] as? String ?: "",
                firstName = data["firstName"] as? String ?: "",
                lastName = data["lastName"] as? String ?: "",
                userType = data["userType"] as? String ?: "USER",
                enabled = data["enabled"] as? Boolean ?: true,
                authorities = authorities
            )
        }
    }
}
