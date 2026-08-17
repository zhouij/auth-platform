package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.AuditLogService
import com.zhouij.authplatform.iam.service.LoginAttemptService
import com.zhouij.authplatform.iam.service.UserService
import jakarta.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.time.Duration

@RestController
@RequestMapping("/internal")
class InternalAuthController(
    private val userService: UserService,
    private val adminUserService: AdminUserService,
    private val loginAttemptService: LoginAttemptService,
    private val auditLogService: AuditLogService
) {
    private val logger = LoggerFactory.getLogger(InternalAuthController::class.java)

    @Value("\${iam.internal-token:dev-internal-token}")
    private lateinit var internalToken: String

    @Value("\${email.verification-required:false}")
    private var verificationRequired: Boolean = false

    @PostMapping("/auth/validate")
    fun validateCredentials(
        @RequestHeader("X-Internal-Token") token: String,
        @RequestBody request: ValidateRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, Any>> {
        if (token != internalToken) {
            logger.warn("Internal auth request rejected: invalid token")
            return ResponseEntity.status(401).build()
        }

        val normalizedEmail = request.email.trim().lowercase()
        val lockout = loginAttemptService.lockoutRemaining(normalizedEmail)
        if (lockout != null) {
            auditLogService.record(
                action = "LOGIN",
                outcome = AuditLogEntity.Outcome.FAILURE,
                target = normalizedEmail,
                ipAddress = clientIp(httpRequest),
                detail = "Account locked out (internal validation)"
            )
            val headers = HttpHeaders()
            headers.set(HttpHeaders.RETRY_AFTER, lockout.seconds.coerceAtLeast(1).toString())
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).headers(headers).body(
                mapOf("error" to "Account temporarily locked")
            )
        }

        return when (request.userType.uppercase()) {
            "ADMIN" -> {
                val admin = adminUserService.validateCredentials(request.email, request.password)
                if (admin != null) {
                    loginAttemptService.recordSuccess(normalizedEmail)
                    adminUserService.recordLogin(admin)
                    val authorities = mutableListOf("ROLE_ADMIN")
                    admin.groups.forEach { group ->
                        authorities.add("ROLE_ADMIN_GROUP_${group.name}")
                    }
                    auditLogService.record(
                        action = "LOGIN",
                        outcome = AuditLogEntity.Outcome.SUCCESS,
                        actorType = "ADMIN",
                        actorId = admin.id.toString(),
                        target = admin.email,
                        ipAddress = clientIp(httpRequest),
                        detail = "Via auth-server"
                    )
                    ResponseEntity.ok(
                        mapOf(
                            "userId" to admin.id.toString(),
                            "userType" to "ADMIN",
                            "email" to admin.email,
                            "username" to (admin.username ?: admin.email.substringBefore('@')),
                            "firstName" to (admin.firstName ?: ""),
                            "lastName" to (admin.lastName ?: ""),
                            "enabled" to admin.enabled,
                            "authorities" to authorities
                        )
                    )
                } else {
                    recordFailedLogin(normalizedEmail, httpRequest)
                    ResponseEntity.status(401).body(
                        mapOf("error" to "Invalid credentials")
                    )
                }
            }
            else -> {
                val user = userService.validateCredentials(request.email, request.password)
                if (user != null) {
                    if (verificationRequired && !user.emailVerified) {
                        auditLogService.record(
                            action = "LOGIN",
                            outcome = AuditLogEntity.Outcome.FAILURE,
                            actorType = "USER",
                            actorId = user.id.toString(),
                            target = user.email,
                            ipAddress = clientIp(httpRequest),
                            detail = "Email not verified (internal validation)"
                        )
                        return ResponseEntity.status(403).body(
                            mapOf("error" to "Email address not verified")
                        )
                    }
                    loginAttemptService.recordSuccess(normalizedEmail)
                    userService.recordLogin(user)
                    auditLogService.record(
                        action = "LOGIN",
                        outcome = AuditLogEntity.Outcome.SUCCESS,
                        actorType = "USER",
                        actorId = user.id.toString(),
                        target = user.email,
                        ipAddress = clientIp(httpRequest),
                        detail = "Via auth-server"
                    )
                    ResponseEntity.ok(
                        mapOf(
                            "userId" to user.id.toString(),
                            "userType" to "USER",
                            "email" to user.email,
                            "username" to (user.username ?: user.email.substringBefore('@')),
                            "firstName" to (user.firstName ?: ""),
                            "lastName" to (user.lastName ?: ""),
                            "enabled" to user.enabled,
                            "authorities" to emptyList<String>()
                        )
                    )
                } else {
                    recordFailedLogin(normalizedEmail, httpRequest)
                    ResponseEntity.status(401).body(
                        mapOf("error" to "Invalid credentials")
                    )
                }
            }
        }
    }

    private fun recordFailedLogin(email: String, httpRequest: HttpServletRequest) {
        loginAttemptService.recordFailure(email)
        auditLogService.record(
            action = "LOGIN",
            outcome = AuditLogEntity.Outcome.FAILURE,
            target = email,
            ipAddress = clientIp(httpRequest),
            detail = "Invalid credentials (internal validation)"
        )
    }

    @GetMapping("/users/{email}")
    fun getUserByEmail(
        @RequestHeader("X-Internal-Token") token: String,
        @PathVariable email: String
    ): ResponseEntity<Map<String, Any>> {
        if (token != internalToken) return ResponseEntity.status(401).build()

        val user = userService.findByEmail(email)
            ?: return ResponseEntity.notFound().build()

        return ResponseEntity.ok(
            mapOf(
                "userId" to user.id.toString(),
                "userType" to "USER",
                "email" to user.email,
                "username" to (user.username ?: user.email.substringBefore('@')),
                "firstName" to (user.firstName ?: ""),
                "lastName" to (user.lastName ?: ""),
                "enabled" to user.enabled,
                "credentialsChangedAt" to user.credentialsChangedAt.toString(),
                "authorities" to emptyList<String>()
            )
        )
    }

    @GetMapping("/admin-users/{email}")
    fun getAdminByEmail(
        @RequestHeader("X-Internal-Token") token: String,
        @PathVariable email: String
    ): ResponseEntity<Map<String, Any>> {
        if (token != internalToken) return ResponseEntity.status(401).build()

        val admin = adminUserService.findByEmail(email)
            ?: return ResponseEntity.notFound().build()

        val authorities = mutableListOf("ROLE_ADMIN")
        admin.groups.forEach { authorities.add("ROLE_ADMIN_GROUP_${it.name}") }

        return ResponseEntity.ok(
            mapOf(
                "userId" to admin.id.toString(),
                "userType" to "ADMIN",
                "email" to admin.email,
                "username" to (admin.username ?: admin.email.substringBefore('@')),
                "firstName" to (admin.firstName ?: ""),
                "lastName" to (admin.lastName ?: ""),
                "enabled" to admin.enabled,
                "credentialsChangedAt" to admin.credentialsChangedAt.toString(),
                "authorities" to authorities
            )
        )
    }

    private fun clientIp(request: HttpServletRequest): String? {
        val forwarded = request.getHeader("X-Forwarded-For") ?: return request.remoteAddr
        return forwarded.split(',').firstOrNull()?.trim()
    }
}

data class ValidateRequest(
    val email: String,
    val password: String,
    val userType: String
)
