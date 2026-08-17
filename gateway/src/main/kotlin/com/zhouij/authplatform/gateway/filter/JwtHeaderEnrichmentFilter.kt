package com.zhouij.authplatform.gateway.filter

import com.zhouij.authplatform.gateway.config.GatewaySecurityProperties
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class JwtHeaderEnrichmentFilter(
    private val properties: GatewaySecurityProperties
) : GlobalFilter, Ordered {

    override fun filter(
        exchange: ServerWebExchange,
        chain: GatewayFilterChain
    ): Mono<Void> {
        val path = exchange.request.uri.path

        // Skip enrichment for public paths
        if (properties.publicPaths.any { pathMatch(it, path) }) {
            return chain.filter(exchange)
        }

        // Note: do NOT use getContext().flatMap { ... }.switchIfEmpty(...) here.
        // chain.filter() returns Mono<Void>, which completes EMPTY, so the
        // switchIfEmpty fallback would fire after a successful downstream
        // response and overwrite it with a 401. Instead, substitute an empty
        // SecurityContext as a sentinel for the "no context" case.
        return ReactiveSecurityContextHolder.getContext()
            .defaultIfEmpty(SecurityContextImpl())
            .flatMap { securityContext ->
                val auth = securityContext.authentication
                if (auth is JwtAuthenticationToken && auth.isAuthenticated) {
                    val jwt = auth.token

                    // Strip potentially forged inbound identity headers, then
                    // re-add them from the verified JWT claims.
                    val sanitizedRequest = exchange.request.mutate()
                        .headers { headers ->
                            headers.remove("X-Authenticated-Subject")
                            headers.remove("X-Authenticated-Client")
                            headers.remove("X-Authenticated-Scopes")
                            headers.remove("X-Authenticated-Roles")
                            headers.remove("X-Authenticated-User-Type")
                            // Forged forwarding headers must not reach the
                            // downstream audit trail — replace them with the
                            // address the gateway actually saw.
                            headers.remove("X-Forwarded-For")
                            headers.remove("X-Forwarded-Host")
                            headers.remove("X-Forwarded-Proto")
                        }
                        .header(HttpHeaders.AUTHORIZATION, "Bearer ${jwt.tokenValue}")
                        .header("X-Authenticated-Subject", jwt.subject ?: "unknown")
                        .header("X-Authenticated-Client", jwt.claims["client_id"]?.toString() ?: "unknown")
                        .header("X-Authenticated-Scopes", scopesFrom(jwt.claims["scope"]))
                        .header(
                            "X-Authenticated-Roles",
                            (jwt.claims["roles"] as? List<*>)?.joinToString(",") ?: ""
                        )
                        .header("X-Authenticated-User-Type", jwt.claims["user_type"]?.toString() ?: "")
                        .header(
                            "X-Forwarded-For",
                            exchange.request.remoteAddress?.address?.hostAddress ?: "unknown"
                        )
                        .build()

                    chain.filter(exchange.mutate().request(sanitizedRequest).build())
                } else {
                    exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                    exchange.response.setComplete()
                }
            }
    }

    override fun getOrder(): Int = Ordered.LOWEST_PRECEDENCE

    private fun pathMatch(pattern: String, path: String): Boolean {
        if (pattern.endsWith("/**")) {
            val prefix = pattern.removeSuffix("/**")
            return path == prefix || path.startsWith("$prefix/")
        }
        return pattern == path
    }

    private fun scopesFrom(claim: Any?): String = when (claim) {
        is String -> claim
        is Collection<*> -> claim.filterIsInstance<String>().joinToString(" ")
        else -> ""
    }
}
