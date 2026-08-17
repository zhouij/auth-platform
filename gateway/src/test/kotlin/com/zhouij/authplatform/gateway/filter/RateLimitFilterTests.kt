package com.zhouij.authplatform.gateway.filter

import com.zhouij.authplatform.gateway.config.GatewaySecurityProperties
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.*
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.http.HttpStatus
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import reactor.core.publisher.Mono
import java.net.InetSocketAddress

class RateLimitFilterTests {

    private val properties = GatewaySecurityProperties().apply {
        rateLimit.enabled = true
        rateLimit.requestsPerMinute = 2
        rateLimit.paths = listOf("/iam/v1/auth/login")
    }
    private val chain = mock(GatewayFilterChain::class.java)
    private val filter = RateLimitFilter(properties)

    @BeforeEach
    fun setUp() {
        reset(chain)
        `when`(chain.filter(any())).thenReturn(Mono.empty())
    }

    private fun exchange(ip: String = "203.0.113.7") =
        MockServerWebExchange.from(
            MockServerHttpRequest.post("/iam/v1/auth/login")
                .remoteAddress(InetSocketAddress(ip, 12345))
        )

    @Test
    fun `passes requests within the limit`() {
        filter.filter(exchange(), chain).block()
        filter.filter(exchange(), chain).block()

        verify(chain, times(2)).filter(any())
    }

    @Test
    fun `rejects requests beyond the per-minute limit with 429`() {
        filter.filter(exchange(), chain).block()
        filter.filter(exchange(), chain).block()

        val blocked = exchange()
        filter.filter(blocked, chain).block()

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, blocked.response.statusCode)
        assertNotNull(blocked.response.headers.getFirst("Retry-After"))
        verify(chain, times(2)).filter(any())
    }

    @Test
    fun `does not limit paths outside the configured set`() {
        val other = MockServerWebExchange.from(
            MockServerHttpRequest.get("/iam/v1/auth/status")
                .remoteAddress(InetSocketAddress("203.0.113.7", 12345))
        )
        repeat(5) { filter.filter(other, chain).block() }

        verify(chain, times(5)).filter(any())
    }

    @Test
    fun `disabled limiter passes everything through`() {
        properties.rateLimit.enabled = false
        val filter = RateLimitFilter(properties)

        repeat(10) { filter.filter(exchange(), chain).block() }

        verify(chain, times(10)).filter(any())
    }
}
