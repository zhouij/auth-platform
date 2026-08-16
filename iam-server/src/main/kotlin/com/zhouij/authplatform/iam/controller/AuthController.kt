package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.AuditLogService
import com.zhouij.authplatform.iam.service.EmailVerificationService
import com.zhouij.authplatform.iam.service.LoginAttemptService
import com.zhouij.authplatform.iam.service.PasswordResetService
import com.zhouij.authplatform.iam.service.UserService
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.*
import java.time.Duration
import java.util.UUID

@RestController
@RequestMapping("/api/v1")
class AuthController(
    private val userService: UserService,
    private val adminUserService: AdminUserService,
    private val passwordResetService: PasswordResetService,
    private val loginAttemptService: LoginAttemptService,
    private val emailVerificationService: EmailVerificationService,
    private val auditLogService: AuditLogService
) {

    @Value("\${email.verification-required:false}")
    private var verificationRequired: Boolean = false

    @PostMapping("/auth/register")
    fun register(
        @RequestBody request: RegisterRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, Any>> {
        return try {
            val user = userService.register(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )
            emailVerificationService.sendVerificationEmail(user)
            auditLogService.record(
                action = "REGISTER",
                outcome = AuditLogEntity.Outcome.SUCCESS,
                actorType = "USER",
                actorId = user.id.toString(),
                target = user.email,
                ipAddress = clientIp(httpRequest)
            )
            ResponseEntity.status(201).body(
                mapOf("userId" to user.id.toString(), "message" to "User registered successfully")
            )
        } catch (e: IllegalArgumentException) {
            auditLogService.record(
                action = "REGISTER",
                outcome = AuditLogEntity.Outcome.FAILURE,
                target = request.email,
                ipAddress = clientIp(httpRequest),
                detail = e.message
            )
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    @PostMapping("/auth/login")
    fun login(
        @RequestBody request: LoginRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, Any>> {
        val normalizedEmail = request.email.trim().lowercase()

        // Brute-force protection: reject while the account is locked out
        val lockout = loginAttemptService.lockoutRemaining(normalizedEmail)
        if (lockout != null) {
            auditLogService.record(
                action = "LOGIN",
                outcome = AuditLogEntity.Outcome.FAILURE,
                target = normalizedEmail,
                ipAddress = clientIp(httpRequest),
                detail = "Account locked out"
            )
            val headers = HttpHeaders()
            headers.set(HttpHeaders.RETRY_AFTER, lockout.seconds.coerceAtLeast(1).toString())
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).headers(headers)
                .body(mapOf<String, Any>("error" to "Too many failed attempts — account temporarily locked"))
        }

        // Try USER first, then ADMIN
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
                    detail = "Email not verified"
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
                ipAddress = clientIp(httpRequest)
            )
            return ResponseEntity.ok(
                mapOf(
                    "userId" to user.id.toString(),
                    "email" to user.email,
                    "username" to (user.username ?: user.email.substringBefore('@')),
                    "firstName" to (user.firstName ?: ""),
                    "lastName" to (user.lastName ?: ""),
                    "userType" to "USER",
                    "enabled" to user.enabled,
                    "emailVerified" to user.emailVerified,
                    "authorities" to emptyList<String>()
                )
            )
        }

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
                ipAddress = clientIp(httpRequest)
            )
            return ResponseEntity.ok(
                mapOf(
                    "userId" to admin.id.toString(),
                    "email" to admin.email,
                    "username" to (admin.username ?: admin.email.substringBefore('@')),
                    "firstName" to (admin.firstName ?: ""),
                    "lastName" to (admin.lastName ?: ""),
                    "userType" to "ADMIN",
                    "enabled" to admin.enabled,
                    "authorities" to authorities
                )
            )
        }

        loginAttemptService.recordFailure(normalizedEmail)
        auditLogService.record(
            action = "LOGIN",
            outcome = AuditLogEntity.Outcome.FAILURE,
            target = normalizedEmail,
            ipAddress = clientIp(httpRequest),
            detail = "Invalid credentials"
        )
        return ResponseEntity.status(401).body(
            mapOf("error" to "Invalid email or password")
        )
    }

    @PostMapping("/auth/forgot-password")
    fun forgotPassword(
        @RequestBody request: ForgotPasswordRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, String>> {
        passwordResetService.requestReset(request.email, request.userType.uppercase())
        auditLogService.record(
            action = "PASSWORD_RESET_REQUESTED",
            outcome = AuditLogEntity.Outcome.SUCCESS,
            target = request.email,
            ipAddress = clientIp(httpRequest),
            detail = "userType=${request.userType}"
        )
        return ResponseEntity.accepted().body(mapOf("message" to "If the account exists, a reset link has been sent"))
    }

    @PostMapping("/auth/reset-password")
    fun resetPassword(
        @RequestBody request: ResetPasswordRequest,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, String>> {
        return when (val result = passwordResetService.completeReset(request.token, request.newPassword)) {
            PasswordResetService.ResetResult.SUCCESS -> {
                auditLogService.record(
                    action = "PASSWORD_RESET_COMPLETED",
                    outcome = AuditLogEntity.Outcome.SUCCESS,
                    ipAddress = clientIp(httpRequest)
                )
                ResponseEntity.ok(mapOf("message" to "Password reset successfully"))
            }
            PasswordResetService.ResetResult.INVALID_TOKEN -> {
                auditLogService.record(
                    action = "PASSWORD_RESET_COMPLETED",
                    outcome = AuditLogEntity.Outcome.FAILURE,
                    ipAddress = clientIp(httpRequest),
                    detail = "Invalid or expired token"
                )
                ResponseEntity.status(400).body(mapOf("error" to "Invalid or expired token"))
            }
            PasswordResetService.ResetResult.TOKEN_USED ->
                ResponseEntity.status(400).body(mapOf("error" to "Token has already been used"))
            PasswordResetService.ResetResult.TOKEN_EXPIRED ->
                ResponseEntity.status(400).body(mapOf("error" to "Token has expired"))
            PasswordResetService.ResetResult.WEAK_PASSWORD ->
                ResponseEntity.status(400).body(mapOf("error" to "Password does not meet strength requirements"))
            PasswordResetService.ResetResult.PASSWORD_REUSED ->
                ResponseEntity.status(400).body(mapOf("error" to "Password was used recently — choose a different one"))
        }
    }

    @GetMapping("/auth/verify-email")
    fun verifyEmail(@RequestParam token: String): ResponseEntity<Map<String, String>> {
        return if (emailVerificationService.verify(token)) {
            ResponseEntity.ok(mapOf("message" to "Email verified successfully"))
        } else {
            ResponseEntity.status(400).body(mapOf("error" to "Invalid or expired verification link"))
        }
    }

    @GetMapping("/status")
    fun status(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<Map<String, Any>> {
        val profile = currentUserProfile(jwt) ?: return ResponseEntity.notFound().build()

        return ResponseEntity.ok(
            mapOf(
                "status" to "ok",
                "service" to "iam-server",
                "user" to profile,
                "token" to tokenSummary(jwt)
            )
        )
    }

    // Self-service: get own profile
    @GetMapping("/me")
    fun getProfile(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<Map<String, Any>> {
        val profile = currentUserProfile(jwt) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(profile)
    }

    private fun currentUserProfile(jwt: Jwt): Map<String, Any>? {
        // The subject is a user UUID for end-user tokens; service-account
        // (client_credentials) tokens carry a client id instead.
        val userId = runCatching { UUID.fromString(jwt.subject) }.getOrNull()
            ?: return null
        val userType = jwt.claims["user_type"] as? String

        return when (userType?.uppercase()) {
            "ADMIN" -> {
                val admin = adminUserService.findById(userId)
                    ?: return null
                val authorities = mutableListOf("ROLE_ADMIN")
                val groupNames = admin.groups.map { it.name }
                admin.groups.forEach { authorities.add("ROLE_ADMIN_GROUP_${it.name}") }
                mapOf(
                    "userId" to admin.id.toString(),
                    "email" to admin.email,
                    "username" to (admin.username ?: admin.email.substringBefore('@')),
                    "firstName" to (admin.firstName ?: ""),
                    "lastName" to (admin.lastName ?: ""),
                    "userType" to "ADMIN",
                    "enabled" to admin.enabled,
                    "authorities" to authorities,
                    "groups" to groupNames,
                    "createdAt" to admin.createdAt.toString()
                )
            }
            else -> {
                val user = userService.findById(userId)
                    ?: return null
                mapOf(
                    "userId" to user.id.toString(),
                    "email" to user.email,
                    "username" to (user.username ?: user.email.substringBefore('@')),
                    "firstName" to (user.firstName ?: ""),
                    "lastName" to (user.lastName ?: ""),
                    "userType" to "USER",
                    "enabled" to user.enabled,
                    "emailVerified" to user.emailVerified,
                    "authorities" to emptyList<String>(),
                    "createdAt" to user.createdAt.toString()
                )
            }
        }
    }

    private fun tokenSummary(jwt: Jwt): Map<String, Any> {
        return mapOf(
            "subject" to jwt.subject,
            "clientId" to (jwt.claims["azp"] ?: ""),
            "scopes" to (jwt.claims["scope"] ?: ""),
            "authorities" to jwt.claims["roles"].toString(),
            "issuedAt" to (jwt.issuedAt?.toString() ?: ""),
            "expiresAt" to (jwt.expiresAt?.toString() ?: "")
        )
    }

    // Self-service: update own profile
    @PutMapping("/me")
    fun updateProfile(
        @RequestBody request: UpdateProfileRequest,
        @AuthenticationPrincipal jwt: Jwt
    ): ResponseEntity<Map<String, String>> {
        val userId = runCatching { UUID.fromString(jwt.subject) }.getOrNull()
            ?: return ResponseEntity.notFound().build()
        val userType = jwt.claims["user_type"] as? String

        return try {
            when (userType?.uppercase()) {
                "ADMIN" -> adminUserService.updateProfile(userId, request.firstName, request.lastName, request.username)
                else -> userService.updateProfile(userId, request.firstName, request.lastName, request.username)
            }
            ResponseEntity.ok(mapOf("message" to "Profile updated"))
        } catch (e: NoSuchElementException) {
            ResponseEntity.notFound().build()
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    // Self-service: change own password
    @PutMapping("/me/password")
    fun changePassword(
        @RequestBody request: ChangePasswordRequest,
        @AuthenticationPrincipal jwt: Jwt,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, String>> {
        val userId = runCatching { UUID.fromString(jwt.subject) }.getOrNull()
            ?: return ResponseEntity.notFound().build()
        val userType = jwt.claims["user_type"] as? String

        val result = when (userType?.uppercase()) {
            "ADMIN" -> adminUserService.changePassword(userId, request.currentPassword, request.newPassword)
            else -> userService.changePassword(userId, request.currentPassword, request.newPassword)
        }

        return when (result) {
            UserService.ChangePasswordResult.SUCCESS -> {
                auditLogService.record(
                    action = "PASSWORD_CHANGED",
                    outcome = AuditLogEntity.Outcome.SUCCESS,
                    actorType = userType,
                    actorId = userId.toString(),
                    ipAddress = clientIp(httpRequest)
                )
                ResponseEntity.ok(mapOf("message" to "Password changed successfully"))
            }
            UserService.ChangePasswordResult.WRONG_PASSWORD -> {
                auditLogService.record(
                    action = "PASSWORD_CHANGED",
                    outcome = AuditLogEntity.Outcome.FAILURE,
                    actorType = userType,
                    actorId = userId.toString(),
                    ipAddress = clientIp(httpRequest),
                    detail = "Current password incorrect"
                )
                ResponseEntity.status(403).body(mapOf("error" to "Current password is incorrect"))
            }
            UserService.ChangePasswordResult.WEAK_PASSWORD ->
                ResponseEntity.status(400).body(mapOf("error" to "New password does not meet strength requirements"))
            UserService.ChangePasswordResult.PASSWORD_REUSED ->
                ResponseEntity.status(400).body(mapOf("error" to "Password was used recently — choose a different one"))
            UserService.ChangePasswordResult.USER_NOT_FOUND ->
                ResponseEntity.notFound().build()
        }
    }

    private fun clientIp(request: HttpServletRequest): String? {
        val forwarded = request.getHeader("X-Forwarded-For") ?: return request.remoteAddr
        return forwarded.split(',').firstOrNull()?.trim()
    }
}

data class RegisterRequest(
    val email: String,
    val password: String,
    val firstName: String? = null,
    val lastName: String? = null
)

data class LoginRequest(
    val email: String,
    val password: String
)

data class ForgotPasswordRequest(
    val email: String,
    val userType: String
)

data class ResetPasswordRequest(
    val token: String,
    val newPassword: String
)

data class UpdateProfileRequest(
    val firstName: String? = null,
    val lastName: String? = null,
    val username: String? = null
)

data class ChangePasswordRequest(
    val currentPassword: String,
    val newPassword: String
)
