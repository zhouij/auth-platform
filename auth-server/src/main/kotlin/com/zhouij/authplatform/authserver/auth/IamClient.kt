package com.zhouij.authplatform.authserver.auth

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import reactor.core.publisher.Mono
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@Component
class IamClient(
    @Value("\${iam.base-url}") private val iamBaseUrl: String,
    @Value("\${iam.internal-token}") private val internalToken: String
) {
    private val logger = LoggerFactory.getLogger(IamClient::class.java)

    private val webClient: WebClient = WebClient.builder()
        .baseUrl(iamBaseUrl)
        .build()

    // Simple circuit breaker state
    private val failureCount = AtomicInteger(0)
    private val circuitOpenRef = AtomicReference<Instant?>(null)
    private val failureThreshold = 5
    private val circuitOpenDuration = Duration.ofSeconds(30)
    private val halfOpenMax = 3
    private val halfOpenCount = AtomicInteger(0)

    private val mapTypeRef = object : ParameterizedTypeReference<Map<String, Any>>() {}

    data class ValidationResult(
        val success: Boolean,
        val principal: IamPrincipal? = null,
        val error: String? = null
    )

    fun validateCredentials(email: String, password: String, userType: String): ValidationResult {
        if (isCircuitOpen()) {
            logger.warn("Circuit breaker is open — failing fast for {}", email)
            return ValidationResult(success = false, error = "Authentication temporarily unavailable")
        }

        return try {
            val response: Map<String, Any>? = webClient.post()
                .uri("/internal/auth/validate")
                .header("X-Internal-Token", internalToken)
                .bodyValue(
                    mapOf(
                        "email" to email,
                        "password" to password,
                        "userType" to userType
                    )
                )
                .retrieve()
                .onStatus(
                    { it == HttpStatus.UNAUTHORIZED }
                ) { _ -> Mono.empty() }
                .bodyToMono(mapTypeRef)
                .block(Duration.ofSeconds(5))

            if (response != null) {
                onSuccess()
                ValidationResult(success = true, principal = IamPrincipal.fromResponse(response))
            } else {
                onSuccess()
                ValidationResult(success = false, error = "Invalid credentials")
            }
        } catch (e: WebClientResponseException) {
            if (e.statusCode.is5xxServerError) onFailure() else onSuccess()
            logger.warn("IAM validation HTTP error: {} {}", e.statusCode, e.message)
            ValidationResult(success = false, error = "Invalid credentials")
        } catch (e: Exception) {
            onFailure()
            logger.error("IAM validation failed", e)
            ValidationResult(success = false, error = "Authentication temporarily unavailable")
        }
    }

    fun isCircuitOpen(): Boolean {
        val openSince = circuitOpenRef.get() ?: return false
        if (Duration.between(openSince, Instant.now()) >= circuitOpenDuration) {
            return halfOpenCount.incrementAndGet() > halfOpenMax
        }
        return true
    }

    private fun onSuccess() {
        circuitOpenRef.set(null)
        failureCount.set(0)
        halfOpenCount.set(0)
    }

    private fun onFailure() {
        val count = failureCount.incrementAndGet()
        if (count >= failureThreshold) {
            circuitOpenRef.set(Instant.now())
            halfOpenCount.set(0)
            logger.warn("Circuit breaker opened after {} failures", count)
        }
    }
}
