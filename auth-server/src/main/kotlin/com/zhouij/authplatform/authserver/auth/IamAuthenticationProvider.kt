package com.zhouij.authplatform.authserver.auth

import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component

@Component
class IamAuthenticationProvider(
    private val iamClient: IamClient
) : AuthenticationProvider {
    private val logger = LoggerFactory.getLogger(IamAuthenticationProvider::class.java)

    override fun authenticate(authentication: Authentication): Authentication? {
        if (authentication !is IamLoginAuthenticationToken) return null

        val email = authentication.principal as? String ?: throw BadCredentialsException("Missing email")
        val password = authentication.credentials as? String ?: throw BadCredentialsException("Missing password")
        val userType = authentication.userType

        if (iamClient.isCircuitOpen()) {
            logger.warn("IAM circuit breaker is open — rejecting login for {}", email)
            throw BadCredentialsException("Authentication temporarily unavailable")
        }

        val result = iamClient.validateCredentials(email, password, userType)

        if (!result.success) {
            logger.info("Login failed for {} (type={}): {}", email, userType, result.error)
            throw BadCredentialsException(result.error ?: "Invalid credentials")
        }

        val principal = result.principal ?: throw BadCredentialsException("Invalid credentials")

        if (!principal.enabled) {
            logger.info("Login rejected — account disabled: {}", email)
            throw DisabledException("Account is disabled")
        }

        logger.info("Login successful: {} (type={})", email, principal.userType)

        return IamLoginAuthenticationToken.authenticated(
            principal = principal,
            credentials = password,
            authorities = principal.authorities
        )
    }

    override fun supports(authentication: Class<*>): Boolean {
        return IamLoginAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
