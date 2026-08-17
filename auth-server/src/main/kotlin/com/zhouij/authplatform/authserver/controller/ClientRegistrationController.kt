package com.zhouij.authplatform.authserver.controller

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.web.bind.annotation.*
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

/**
 * Minimal dynamic client registration (RFC 7591-inspired). Clients are created
 * in the database with a generated secret; the endpoint is DISABLED unless a
 * registration token is configured (`auth.client-registration.token`), because
 * open registration is dangerous on a production authorization server.
 *
 * Mounted under the /internal path space like the other trusted-service
 * endpoints, so the same X-Internal-Token-style access rules apply;
 * additionally requires `Authorization: Bearer <registration token>`.
 */
@RestController
@RequestMapping("/internal/clients")
class ClientRegistrationController(
    private val registeredClientRepository: RegisteredClientRepository
) {
    private val logger = LoggerFactory.getLogger(ClientRegistrationController::class.java)

    @Value("\${auth.client-registration.token:}")
    private lateinit var registrationToken: String

    private val passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
    private val secureRandom = SecureRandom()

    companion object {
        private val SUPPORTED_GRANTS = setOf(
            AuthorizationGrantType.AUTHORIZATION_CODE,
            AuthorizationGrantType.CLIENT_CREDENTIALS,
            AuthorizationGrantType.REFRESH_TOKEN
        )
        private val DEFAULT_SCOPES = setOf("openid", "profile", "read")
    }

    @PostMapping
    fun register(
        @RequestHeader(value = "Authorization", required = false) authorization: String?,
        @RequestBody request: ClientRegistrationRequest
    ): ResponseEntity<Map<String, Any>> {
        if (registrationToken.isBlank() || !isAuthorized(authorization)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build()
        }

        val errors = validate(request)
        if (errors.isNotEmpty()) {
            return ResponseEntity.badRequest().body(mapOf("error" to "invalid_client_metadata", "details" to errors))
        }

        val clientId = "client-${UUID.randomUUID()}"
        val clientSecret = request.clientSecret?.takeIf { it.isNotBlank() } ?: generateSecret()
        val grantTypes = request.grantTypes.orEmpty().map(::toGrantType)
        val requiresConsent = AuthorizationGrantType.AUTHORIZATION_CODE in grantTypes

        val client = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(passwordEncoder.encode(clientSecret))
            .clientName(request.clientName ?: clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantTypes { it.addAll(grantTypes) }
            .redirectUris { it.addAll(request.redirectUris.orEmpty()) }
            .scopes { it.addAll(request.scopes.orEmpty().ifEmpty { DEFAULT_SCOPES }) }
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(requiresConsent)
                    .requireProofKey(AuthorizationGrantType.AUTHORIZATION_CODE in grantTypes)
                    .build()
            )
            .build()

        registeredClientRepository.save(client)
        logger.info("Registered new client: clientId={}, grants={}, scopes={}", clientId, grantTypes, client.scopes)

        return ResponseEntity.status(HttpStatus.CREATED).body(
            mapOf(
                "client_id" to clientId,
                "client_secret" to clientSecret,
                "client_id_issued_at" to Instant.now().epochSecond,
                "client_secret_expires_at" to 0,
                "client_name" to client.clientName,
                "redirect_uris" to request.redirectUris.orEmpty(),
                "grant_types" to request.grantTypes.orEmpty(),
                "token_endpoint_auth_method" to "client_secret_basic",
                "scopes" to client.scopes
            )
        )
    }

    private fun isAuthorized(authorization: String?): Boolean {
        val presented = authorization
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer")
            ?.trim()
        return presented != null && presented == registrationToken
    }

    private fun validate(request: ClientRegistrationRequest): List<String> {
        val errors = mutableListOf<String>()
        if (request.clientName.isNullOrBlank()) errors += "client_name is required"
        if (request.redirectUris.orEmpty().isEmpty() || request.redirectUris.orEmpty().any { it.isBlank() }) {
            errors += "at least one valid redirect_uri is required"
        }
        if (request.grantTypes.orEmpty().isEmpty()) {
            errors += "grant_types must not be empty"
        } else {
            val invalid = request.grantTypes.orEmpty().filter { g -> runCatching { toGrantType(g) }.isFailure }
            if (invalid.isNotEmpty()) errors += "unsupported grant_type(s): $invalid"
        }
        request.clientSecret?.let { secret ->
            if (secret.isNotBlank() && secret.length < 16) {
                errors += "client_secret must be at least 16 characters"
            }
        }
        return errors
    }

    private fun toGrantType(grant: String): AuthorizationGrantType = when (grant) {
        "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE
        "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS
        "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN
        else -> throw IllegalArgumentException("Unsupported grant type: $grant")
    }

    private fun generateSecret(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..32).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
    }
}

data class ClientRegistrationRequest(
    val clientName: String? = null,
    val redirectUris: List<String>? = emptyList(),
    val grantTypes: List<String>? = emptyList(),
    val scopes: Set<String>? = emptySet(),
    val clientSecret: String? = null
)
