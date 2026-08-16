package com.zhouij.authplatform.gateway.filter

import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

/**
 * Overwrites the forwarding headers on every inbound request with values the
 * gateway actually observed, so clients cannot forge X-Forwarded-For/-Host/
 * -Proto (used downstream for audit IPs and URL construction). Runs before
 * routing and before any security processing.
 */
@Component
class ForwardedHeadersSanitizerFilter : GlobalFilter, Ordered {

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val clientIp = exchange.request.remoteAddress?.address?.hostAddress ?: "unknown"
        val sanitized: ServerHttpRequest = exchange.request.mutate()
            .headers { headers ->
                headers.remove("X-Forwarded-For")
                headers.remove("X-Forwarded-Host")
                headers.remove("X-Forwarded-Proto")
                headers.remove("Forwarded")
                headers.remove("X-Real-IP")
            }
            .header("X-Forwarded-For", clientIp)
            .header("X-Real-IP", clientIp)
            .build()
        return chain.filter(exchange.mutate().request(sanitized).build())
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE
}
