package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.PasswordResetService
import com.zhouij.authplatform.iam.service.UserService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.*
import java.util.UUID

@RestController
@RequestMapping("/api/v1")
class AuthController(
    private val userService: UserService,
    private val adminUserService: AdminUserService,
    private val passwordResetService: PasswordResetService
) {

    @PostMapping("/auth/register")
    fun register(@RequestBody request: RegisterRequest): ResponseEntity<Map<String, Any>> {
        return try {
            val user = userService.register(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName
            )
            ResponseEntity.status(201).body(
                mapOf("userId" to user.id.toString(), "message" to "User registered successfully")
            )
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    @PostMapping("/auth/login")
    fun login(@RequestBody request: LoginRequest): ResponseEntity<Map<String, Any>> {
        // Try USER first, then ADMIN
        val user = userService.validateCredentials(request.email, request.password)
        if (user != null) {
            userService.recordLogin(user)
            return ResponseEntity.ok(
                mapOf(
                    "userId" to user.id.toString(),
                    "email" to user.email,
                    "username" to (user.username ?: user.email.substringBefore('@')),
                    "firstName" to (user.firstName ?: ""),
                    "lastName" to (user.lastName ?: ""),
                    "userType" to "USER",
                    "enabled" to user.enabled,
                    "authorities" to emptyList<String>()
                )
            )
        }

        val admin = adminUserService.validateCredentials(request.email, request.password)
        if (admin != null) {
            adminUserService.recordLogin(admin)
            val authorities = mutableListOf("ROLE_ADMIN")
            admin.groups.forEach { group ->
                authorities.add("ROLE_ADMIN_GROUP_${group.name}")
            }
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

        return ResponseEntity.status(401).body(
            mapOf("error" to "Invalid email or password")
        )
    }

    @PostMapping("/auth/forgot-password")
    fun forgotPassword(@RequestBody request: ForgotPasswordRequest): ResponseEntity<Map<String, String>> {
        passwordResetService.requestReset(request.email, request.userType.uppercase())
        return ResponseEntity.accepted().body(mapOf("message" to "If the account exists, a reset link has been sent"))
    }

    @PostMapping("/auth/reset-password")
    fun resetPassword(@RequestBody request: ResetPasswordRequest): ResponseEntity<Map<String, String>> {
        return when (val result = passwordResetService.completeReset(request.token, request.newPassword)) {
            PasswordResetService.ResetResult.SUCCESS ->
                ResponseEntity.ok(mapOf("message" to "Password reset successfully"))
            PasswordResetService.ResetResult.INVALID_TOKEN ->
                ResponseEntity.status(400).body(mapOf("error" to "Invalid or expired token"))
            PasswordResetService.ResetResult.TOKEN_USED ->
                ResponseEntity.status(400).body(mapOf("error" to "Token has already been used"))
            PasswordResetService.ResetResult.TOKEN_EXPIRED ->
                ResponseEntity.status(400).body(mapOf("error" to "Token has expired"))
            PasswordResetService.ResetResult.WEAK_PASSWORD ->
                ResponseEntity.status(400).body(mapOf("error" to "Password does not meet strength requirements"))
        }
    }

    // Self-service: get own profile
    @GetMapping("/me")
    fun getProfile(@AuthenticationPrincipal jwt: JwtAuthenticationToken): ResponseEntity<Map<String, Any>> {
        val userId = UUID.fromString(jwt.token.subject)
        val userType = jwt.token.claims["user_type"] as? String

        return when (userType?.uppercase()) {
            "ADMIN" -> {
                val admin = adminUserService.findById(userId)
                    ?: return ResponseEntity.notFound().build()
                val authorities = mutableListOf("ROLE_ADMIN")
                val groupNames = admin.groups.map { it.name }
                admin.groups.forEach { authorities.add("ROLE_ADMIN_GROUP_${it.name}") }
                ResponseEntity.ok(
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
                )
            }
            else -> {
                val user = userService.findById(userId)
                    ?: return ResponseEntity.notFound().build()
                ResponseEntity.ok(
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
                )
            }
        }
    }

    // Self-service: update own profile
    @PutMapping("/me")
    fun updateProfile(
        @RequestBody request: UpdateProfileRequest,
        @AuthenticationPrincipal jwt: JwtAuthenticationToken
    ): ResponseEntity<Map<String, String>> {
        val userId = UUID.fromString(jwt.token.subject)
        val userType = jwt.token.claims["user_type"] as? String

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
        @AuthenticationPrincipal jwt: JwtAuthenticationToken
    ): ResponseEntity<Map<String, String>> {
        val userId = UUID.fromString(jwt.token.subject)
        val userType = jwt.token.claims["user_type"] as? String

        val result = when (userType?.uppercase()) {
            "ADMIN" -> adminUserService.changePassword(userId, request.currentPassword, request.newPassword)
            else -> userService.changePassword(userId, request.currentPassword, request.newPassword)
        }

        return when (result) {
            UserService.ChangePasswordResult.SUCCESS ->
                ResponseEntity.ok(mapOf("message" to "Password changed successfully"))
            UserService.ChangePasswordResult.WRONG_PASSWORD ->
                ResponseEntity.status(403).body(mapOf("error" to "Current password is incorrect"))
            UserService.ChangePasswordResult.WEAK_PASSWORD ->
                ResponseEntity.status(400).body(mapOf("error" to "New password does not meet strength requirements"))
            UserService.ChangePasswordResult.USER_NOT_FOUND ->
                ResponseEntity.notFound().build()
        }
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
