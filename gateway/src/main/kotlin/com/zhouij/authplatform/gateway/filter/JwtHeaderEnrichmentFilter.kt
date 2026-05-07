package com.zhouij.authplatform.gateway.filter

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class JwtHeaderEnrichmentFilter : GlobalFilter, Ordered {

    private val logger = LoggerFactory.getLogger(JwtHeaderEnrichmentFilter::class.java)

    @Value("\${gateway.public-paths}")
    private lateinit var publicPaths: List<String>

    override fun filter(
        exchange: ServerWebExchange,
        chain: GatewayFilterChain
    ): Mono<Void> {
        val path = exchange.request.uri.path

        // Skip enrichment for public paths
        if (publicPaths.any { pathMatch(it, path) }) {
            return chain.filter(exchange)
        }

        return ReactiveSecurityContextHolder.getContext()
            .flatMap { securityContext ->
                val auth = securityContext.authentication
                if (auth is JwtAuthenticationToken && auth.isAuthenticated) {
                    val jwt = auth.token

                    // Strip potentially forged inbound headers
                    val sanitizedRequest = exchange.request.mutate()
                        .headers { headers ->
                            headers.remove("X-Authenticated-Subject")
                            headers.remove("X-Authenticated-Client")
                            headers.remove("X-Authenticated-Scopes")
                            headers.remove("X-Authenticated-Roles")
                            headers.remove("X-Authenticated-User-Type")
                        }
                        .header(HttpHeaders.AUTHORIZATION, "Bearer ${jwt.tokenValue}")
                        .header("X-Authenticated-Subject", jwt.subject ?: "unknown")
                        .header("X-Authenticated-Client", jwt.claims["client_id"]?.toString() ?: "unknown")
                        .header("X-Authenticated-Scopes", jwt.claims["scope"]?.toString() ?: "")
                        .header("X-Authenticated-Roles",
                            (jwt.claims["roles"] as? List<*>)?.joinToString(",") ?: "")
                        .header("X-Authenticated-User-Type", jwt.claims["user_type"]?.toString() ?: "")
                        .build()

                    chain.filter(exchange.mutate().request(sanitizedRequest).build())
                } else {
                    exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                    exchange.response.setComplete()
                }
            }
            .switchIfEmpty(
                Mono.defer {
                    exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                    exchange.response.setComplete()
                }
            )
    }

    override fun getOrder(): Int = Ordered.LOWEST_PRECEDENCE

    private fun pathMatch(pattern: String, path: String): Boolean {
        if (pattern.endsWith("/**")) {
            val prefix = pattern.removeSuffix("/**")
            return path == prefix || path.startsWith("$prefix/")
        }
        return pattern == path
    }
}
