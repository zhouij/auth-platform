package com.zhouij.authplatform.gateway.filter

import com.zhouij.authplatform.gateway.config.GatewaySecurityProperties
import org.slf4j.LoggerFactory
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Closes the revocation gap for already-issued access tokens: when enabled,
 * the jti of each presented JWT is checked against the auth-server denylist
 * (populated by /internal/auth/revoke-user/{id}). Positive hits are cached for
 * the remainder of the token lifetime (bounded by the configured cache TTL);
 * negative results are cached for [GatewaySecurityProperties.RevocationCheckProperties.cacheSeconds].
 *
 * Disabled by default (no dependency on auth-server reachability); enable with
 * GATEWAY_REVOCATION_CHECK_ENABLED=true and a shared internal token.
 */
@Component
@Order(-50) // after Spring Security's WebFilterChainProxy (-100) so the JWT auth is available
class TokenRevocationCheckFilter(
    private val properties: GatewaySecurityProperties
) : WebFilter {

    private val logger = LoggerFactory.getLogger(TokenRevocationCheckFilter::class.java)

    private data class CacheEntry(val revoked: Boolean, val expiresAt: Instant)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    private val webClient: WebClient by lazy {
        WebClient.builder()
            .baseUrl(properties.revocationCheck.authServerBaseUrl)
            .build()
    }

    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val config = properties.revocationCheck
        if (!config.enabled) return chain.filter(exchange)

        return ReactiveSecurityContextHolder.getContext()
            .defaultIfEmpty(SecurityContextImpl())
            .flatMap { securityContext ->
                val auth = securityContext.authentication
                if (auth is JwtAuthenticationToken && auth.isAuthenticated) {
                    val jwt = auth.token
                    val jti = jwt.claims["jti"] as? String
                    if (jti == null) {
                        chain.filter(exchange)
                    } else {
                        checkRevoked(jti, jwt.expiresAt).flatMap { revoked ->
                            if (revoked) {
                                logger.warn("Rejected request with revoked token (jti={})", jti)
                                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                                exchange.response.setComplete()
                            } else {
                                chain.filter(exchange)
                            }
                        }
                    }
                } else {
                    chain.filter(exchange)
                }
            }
    }

    private fun checkRevoked(jti: String, tokenExpiry: Instant?): Mono<Boolean> {
        val cached = cache[jti]
        val now = Instant.now()
        if (cached != null && cached.expiresAt.isAfter(now)) {
            return Mono.just(cached.revoked)
        }

        return webClient.get()
            .uri("/internal/tokens/revoked/{jti}", jti)
            .header("X-Internal-Token", properties.revocationCheck.internalToken)
            .retrieve()
            .bodyToMono<Map<String, Any>>()
            .map { response -> response["revoked"] as? Boolean ?: false }
            .onErrorResume { e ->
                // Fail open on auth-server errors (availability > strictness),
                // but keep the failure visible in the logs.
                logger.error("Revocation check failed for jti={}: {}", jti, e.message)
                Mono.just(false)
            }
            .map { revoked ->
                val cacheUntil = if (revoked) {
                    (tokenExpiry ?: now.plusSeconds(60)).coerceAtMost(now.plusSeconds(86400))
                } else {
                    now.plusSeconds(properties.revocationCheck.cacheSeconds)
                }
                if (cacheUntil.isAfter(now)) {
                    cache[jti] = CacheEntry(revoked, cacheUntil)
                }
                revoked
            }
    }
}
