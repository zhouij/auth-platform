package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.domain.AuditLogEntity
import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.AuditLogService
import com.zhouij.authplatform.iam.service.EmailVerificationService
import com.zhouij.authplatform.iam.service.PasswordResetService
import com.zhouij.authplatform.iam.service.TokenRevocationClient
import com.zhouij.authplatform.iam.service.UserService
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.*
import java.util.UUID

@RestController
@RequestMapping("/api/v1")
class AuthController(
    private val userService: UserService,
    private val adminUserService: AdminUserService,
    private val passwordResetService: PasswordResetService,
    private val emailVerificationService: EmailVerificationService,
    private val auditLogService: AuditLogService,
    private val tokenRevocationClient: TokenRevocationClient
) {

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

    // NOTE: there is deliberately no public /api/v1/auth/login endpoint.
    // Credential checks happen only over the X-Internal-Token-protected
    // /internal/auth/validate (used by auth-server). The old debug-style login
    // endpoint returned profile data without any token and was removed.

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

    // Self-service: data export (GDPR art. 20)
    @GetMapping("/me/export")
    fun exportData(
        @AuthenticationPrincipal jwt: Jwt,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, Any>> {
        val userId = runCatching { UUID.fromString(jwt.subject) }.getOrNull()
            ?: return ResponseEntity.notFound().build()
        val userType = jwt.claims["user_type"] as? String

        val export = when (userType?.uppercase()) {
            "ADMIN" -> adminUserService.findById(userId)?.let { admin ->
                mapOf<String, Any>(
                    "userType" to "ADMIN",
                    "userId" to admin.id.toString(),
                    "email" to admin.email,
                    "username" to (admin.username ?: ""),
                    "firstName" to (admin.firstName ?: ""),
                    "lastName" to (admin.lastName ?: ""),
                    "enabled" to admin.enabled,
                    "groups" to admin.groups.map { it.name },
                    "createdAt" to admin.createdAt.toString(),
                    "updatedAt" to admin.updatedAt.toString(),
                    "lastLoginAt" to (admin.lastLoginAt?.toString() ?: ""),
                    "credentialsChangedAt" to admin.credentialsChangedAt.toString()
                )
            } ?: return ResponseEntity.notFound().build()
            else -> userService.findById(userId)?.let { user ->
                mapOf<String, Any>(
                    "userType" to "USER",
                    "userId" to user.id.toString(),
                    "email" to user.email,
                    "username" to (user.username ?: ""),
                    "firstName" to (user.firstName ?: ""),
                    "lastName" to (user.lastName ?: ""),
                    "enabled" to user.enabled,
                    "emailVerified" to user.emailVerified,
                    "createdAt" to user.createdAt.toString(),
                    "updatedAt" to user.updatedAt.toString(),
                    "lastLoginAt" to (user.lastLoginAt?.toString() ?: ""),
                    "credentialsChangedAt" to user.credentialsChangedAt.toString()
                )
            } ?: return ResponseEntity.notFound().build()
        }

        auditLogService.record(
            action = "DATA_EXPORTED",
            outcome = AuditLogEntity.Outcome.SUCCESS,
            actorType = userType,
            actorId = userId.toString(),
            target = export["email"] as? String,
            ipAddress = clientIp(httpRequest)
        )
        return ResponseEntity.ok(export)
    }

    // Self-service: right to erasure (GDPR art. 17) — anonymizes the account,
    // disables it, clears associated data, and revokes outstanding tokens.
    @DeleteMapping("/me")
    fun deleteAccount(
        @AuthenticationPrincipal jwt: Jwt,
        httpRequest: HttpServletRequest
    ): ResponseEntity<Map<String, String>> {
        val userId = runCatching { UUID.fromString(jwt.subject) }.getOrNull()
            ?: return ResponseEntity.notFound().build()
        val userType = jwt.claims["user_type"] as? String

        val email = when (userType?.uppercase()) {
            "ADMIN" -> adminUserService.findById(userId)?.email
            else -> userService.findById(userId)?.email
        } ?: return ResponseEntity.notFound().build()

        when (userType?.uppercase()) {
            "ADMIN" -> adminUserService.deleteAccount(userId)
            else -> userService.deleteAccount(userId)
        }
        tokenRevocationClient.revokeAllTokens(userId.toString())

        auditLogService.record(
            action = "ACCOUNT_DELETED",
            outcome = AuditLogEntity.Outcome.SUCCESS,
            actorType = userType,
            actorId = userId.toString(),
            target = email,
            ipAddress = clientIp(httpRequest)
        )
        return ResponseEntity.ok(mapOf("message" to "Account deleted"))
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
