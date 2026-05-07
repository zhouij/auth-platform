package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.UserService
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/internal")
class InternalAuthController(
    private val userService: UserService,
    private val adminUserService: AdminUserService
) {
    private val logger = LoggerFactory.getLogger(InternalAuthController::class.java)

    @Value("\${iam.internal-token:dev-internal-token}")
    private lateinit var internalToken: String

    @PostMapping("/auth/validate")
    fun validateCredentials(
        @RequestHeader("X-Internal-Token") token: String,
        @RequestBody request: ValidateRequest
    ): ResponseEntity<Map<String, Any>> {
        if (token != internalToken) {
            logger.warn("Internal auth request rejected: invalid token")
            return ResponseEntity.status(401).build()
        }

        return when (request.userType.uppercase()) {
            "ADMIN" -> {
                val admin = adminUserService.validateCredentials(request.email, request.password)
                if (admin != null) {
                    val authorities = mutableListOf("ROLE_ADMIN")
                    admin.groups.forEach { group ->
                        authorities.add("ROLE_ADMIN_GROUP_${group.name}")
                    }
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
                    ResponseEntity.status(401).body(
                        mapOf("error" to "Invalid credentials")
                    )
                }
            }
            else -> {
                val user = userService.validateCredentials(request.email, request.password)
                if (user != null) {
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
                    ResponseEntity.status(401).body(
                        mapOf("error" to "Invalid credentials")
                    )
                }
            }
        }
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
}

data class ValidateRequest(
    val email: String,
    val password: String,
    val userType: String
)
