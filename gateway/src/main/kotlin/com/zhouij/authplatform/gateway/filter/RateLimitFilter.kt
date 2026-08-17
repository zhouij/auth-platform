package com.zhouij.authplatform.gateway.filter

import com.zhouij.authplatform.gateway.config.GatewaySecurityProperties
import org.slf4j.LoggerFactory
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.GlobalFilter
import org.springframework.core.Ordered
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Simple per-client-IP fixed-window rate limiter for abuse-prone endpoints
 * (login, registration, password reset). In-memory by design: for multi-
 * replica deployments swap in the Redis RequestRateLimiter or an equivalent
 * shared store.
 */
@Component
class RateLimitFilter(
    private val properties: GatewaySecurityProperties
) : GlobalFilter, Ordered {

    private val logger = LoggerFactory.getLogger(RateLimitFilter::class.java)

    private data class Window(val start: AtomicReference<Instant>, val count: AtomicInteger)

    private val windows = ConcurrentHashMap<String, Window>()
    private var lastCleanup = AtomicReference(Instant.now())

    override fun filter(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val config = properties.rateLimit
        if (!config.enabled) return chain.filter(exchange)

        val path = exchange.request.uri.path
        if (config.paths.none { path == it }) return chain.filter(exchange)

        val ip = exchange.request.remoteAddress?.address?.hostAddress ?: "unknown"
        val key = "$ip|$path"
        val now = Instant.now()

        // Opportunistic cleanup of stale windows (roughly once a minute)
        if (Duration.between(lastCleanup.get(), now).seconds > 60 &&
            lastCleanup.compareAndSet(lastCleanup.get(), now)
        ) {
            val cutoff = now.minusSeconds(120)
            windows.entries.removeIf { it.value.start.get().isBefore(cutoff) }
        }

        val window = windows.computeIfAbsent(key) {
            Window(AtomicReference(now), AtomicInteger(0))
        }

        // Roll the window when it is older than one minute
        val windowStart = window.start.updateAndGet { start ->
            if (Duration.between(start, now).seconds >= 60) now else start
        }
        val count = window.count.incrementAndGet()

        if (count > config.requestsPerMinute) {
            logger.warn(
                "Rate limit exceeded for {} on {}: {}/{} per minute",
                ip, path, count, config.requestsPerMinute
            )
            exchange.response.statusCode = HttpStatus.TOO_MANY_REQUESTS
            exchange.response.headers.set("Retry-After", "60")
            exchange.response.headers.set("X-RateLimit-Limit", config.requestsPerMinute.toString())
            return exchange.response.setComplete()
        }

        exchange.response.headers.set("X-RateLimit-Remaining", (config.requestsPerMinute - count).coerceAtLeast(0).toString())
        return chain.filter(exchange)
    }

    override fun getOrder(): Int = Ordered.HIGHEST_PRECEDENCE + 10
}
