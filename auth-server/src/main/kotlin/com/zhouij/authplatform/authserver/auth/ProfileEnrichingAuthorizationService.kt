package com.zhouij.authplatform.authserver.auth

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import java.security.Principal

/**
 * Decorates the JDBC authorization service so that the persisted
 * `OAuth2Authorization` attributes contain only types that Spring Security 7's
 * Jackson `PolymorphicTypeValidator` can deserialize.
 *
 * The custom [IamPrincipal] is not a subtype of an allow-listed class, so it
 * cannot be round-tripped through the `oauth2_authorization.attributes` JSON.
 * This decorator replaces the resource-owner authentication with a standard
 * [UsernamePasswordAuthenticationToken] whose principal is the user id, and
 * stores the profile claims as a plain string map attribute. The token
 * customizer reads the profile map on refresh flows.
 */
class ProfileEnrichingAuthorizationService(
    private val delegate: OAuth2AuthorizationService
) : OAuth2AuthorizationService {

    override fun save(authorization: OAuth2Authorization) {
        delegate.save(enrich(authorization))
    }

    override fun remove(authorization: OAuth2Authorization) = delegate.remove(authorization)

    override fun findById(id: String): OAuth2Authorization? = delegate.findById(id)

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? =
        delegate.findByToken(token, tokenType)

    private fun enrich(authorization: OAuth2Authorization): OAuth2Authorization {
        val principalAttribute = authorization.getAttribute<Any>(Principal::class.java.name)
            ?: return authorization
        val iamPrincipal = (principalAttribute as? Authentication)?.principal as? IamPrincipal
            ?: return authorization

        return OAuth2Authorization.from(authorization)
            .attribute(
                Principal::class.java.name,
                UsernamePasswordAuthenticationToken.authenticated(
                    iamPrincipal.userId,
                    null,
                    iamPrincipal.authorities
                )
            )
            .attribute(
                PROFILE_ATTRIBUTE,
                mapOf(
                    "userId" to iamPrincipal.userId,
                    "email" to iamPrincipal.email,
                    "preferred_username" to iamPrincipal.username,
                    "given_name" to iamPrincipal.firstName,
                    "family_name" to iamPrincipal.lastName,
                    "user_type" to iamPrincipal.userType,
                    "roles" to iamPrincipal.authorities
                        .mapNotNull { it.authority }
                        .filter { it.startsWith("ROLE_") }
                        .map { it.removePrefix("ROLE_") }
                )
            )
            .build()
    }

    companion object {
        const val PROFILE_ATTRIBUTE = "com.zhouij.authplatform.iam.profile"
    }
}
