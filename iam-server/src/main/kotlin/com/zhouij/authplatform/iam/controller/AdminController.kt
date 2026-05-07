package com.zhouij.authplatform.iam.controller

import com.zhouij.authplatform.iam.service.AdminUserService
import com.zhouij.authplatform.iam.service.UserService
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/admin")
class AdminController(
    private val userService: UserService,
    private val adminUserService: AdminUserService
) {

    // === Regular User Management ===

    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun listUsers(): ResponseEntity<List<Map<String, Any>>> {
        val users = userService.listAll().map { user ->
            mapOf(
                "id" to user.id.toString(),
                "email" to user.email,
                "username" to (user.username ?: ""),
                "firstName" to (user.firstName ?: ""),
                "lastName" to (user.lastName ?: ""),
                "enabled" to user.enabled,
                "emailVerified" to user.emailVerified,
                "createdAt" to user.createdAt.toString(),
                "lastLoginAt" to (user.lastLoginAt?.toString() ?: "")
            )
        }
        return ResponseEntity.ok(users)
    }

    @GetMapping("/users/{email}")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun getUser(@PathVariable email: String): ResponseEntity<Map<String, Any>> {
        val user = userService.findByEmail(email)
            ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(
            mapOf(
                "id" to user.id.toString(),
                "email" to user.email,
                "username" to (user.username ?: ""),
                "firstName" to (user.firstName ?: ""),
                "lastName" to (user.lastName ?: ""),
                "enabled" to user.enabled,
                "emailVerified" to user.emailVerified,
                "createdAt" to user.createdAt.toString(),
                "lastLoginAt" to (user.lastLoginAt?.toString() ?: "")
            )
        )
    }

    @PutMapping("/users/{email}")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun updateUser(
        @PathVariable email: String,
        @RequestBody request: AdminUpdateRequest
    ): ResponseEntity<Map<String, String>> {
        return try {
            userService.adminUpdateProfile(email, request.firstName, request.lastName, request.username)
            ResponseEntity.ok(mapOf("message" to "User updated"))
        } catch (e: NoSuchElementException) {
            ResponseEntity.notFound().build()
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    @PutMapping("/users/{email}/password")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun resetUserPassword(
        @PathVariable email: String,
        @RequestBody request: AdminResetPasswordRequest
    ): ResponseEntity<Map<String, String>> {
        return if (userService.adminResetPassword(email, request.newPassword)) {
            ResponseEntity.ok(mapOf("message" to "Password reset successfully"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @PostMapping("/users/{email}/disable")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun disableUser(@PathVariable email: String): ResponseEntity<Map<String, String>> {
        return if (userService.disable(email)) {
            ResponseEntity.ok(mapOf("message" to "User disabled"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @PostMapping("/users/{email}/enable")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_USER_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun enableUser(@PathVariable email: String): ResponseEntity<Map<String, String>> {
        return if (userService.enable(email)) {
            ResponseEntity.ok(mapOf("message" to "User enabled"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    // === Admin User Management ===

    @GetMapping("/admins")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun listAdmins(): ResponseEntity<List<Map<String, Any>>> {
        val admins = adminUserService.listAll().map { admin ->
            mapOf(
                "id" to admin.id.toString(),
                "email" to admin.email,
                "username" to (admin.username ?: ""),
                "firstName" to (admin.firstName ?: ""),
                "lastName" to (admin.lastName ?: ""),
                "enabled" to admin.enabled,
                "groups" to admin.groups.map { it.name },
                "createdAt" to admin.createdAt.toString(),
                "lastLoginAt" to (admin.lastLoginAt?.toString() ?: "")
            )
        }
        return ResponseEntity.ok(admins)
    }

    @GetMapping("/admins/{email}")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun getAdmin(@PathVariable email: String): ResponseEntity<Map<String, Any>> {
        val admin = adminUserService.findByEmail(email)
            ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(
            mapOf(
                "id" to admin.id.toString(),
                "email" to admin.email,
                "username" to (admin.username ?: ""),
                "firstName" to (admin.firstName ?: ""),
                "lastName" to (admin.lastName ?: ""),
                "enabled" to admin.enabled,
                "groups" to admin.groups.map { it.name },
                "createdAt" to admin.createdAt.toString(),
                "lastLoginAt" to (admin.lastLoginAt?.toString() ?: "")
            )
        )
    }

    @PostMapping("/admins")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun createAdmin(@RequestBody request: CreateAdminRequest): ResponseEntity<Map<String, Any>> {
        return try {
            val admin = adminUserService.createAdmin(
                email = request.email,
                password = request.password,
                firstName = request.firstName,
                lastName = request.lastName,
                groupNames = request.groupNames
            )
            ResponseEntity.status(201).body(
                mapOf(
                    "userId" to admin.id.toString(),
                    "email" to admin.email,
                    "groups" to admin.groups.map { it.name },
                    "message" to "Admin created successfully"
                )
            )
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    @PutMapping("/admins/{email}")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun updateAdmin(
        @PathVariable email: String,
        @RequestBody request: UpdateAdminRequest
    ): ResponseEntity<Map<String, String>> {
        return try {
            adminUserService.updateAdminDetails(
                email, request.firstName, request.lastName, request.username, request.groupNames
            )
            ResponseEntity.ok(mapOf("message" to "Admin updated"))
        } catch (e: NoSuchElementException) {
            ResponseEntity.notFound().build()
        } catch (e: IllegalArgumentException) {
            ResponseEntity.status(409).body(mapOf("error" to (e.message ?: "Conflict")))
        }
    }

    @PutMapping("/admins/{email}/password")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun resetAdminPassword(
        @PathVariable email: String,
        @RequestBody request: AdminResetPasswordRequest
    ): ResponseEntity<Map<String, String>> {
        return if (adminUserService.adminResetPassword(email, request.newPassword)) {
            ResponseEntity.ok(mapOf("message" to "Password reset successfully"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @PostMapping("/admins/{email}/disable")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun disableAdmin(@PathVariable email: String): ResponseEntity<Map<String, String>> {
        return if (adminUserService.disable(email)) {
            ResponseEntity.ok(mapOf("message" to "Admin disabled"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    @PostMapping("/admins/{email}/enable")
    @PreAuthorize("hasAnyRole('ADMIN_GROUP_ADMIN_MANAGEMENT', 'ADMIN_GROUP_FULL_ACCESS')")
    fun enableAdmin(@PathVariable email: String): ResponseEntity<Map<String, String>> {
        return if (adminUserService.enable(email)) {
            ResponseEntity.ok(mapOf("message" to "Admin enabled"))
        } else {
            ResponseEntity.notFound().build()
        }
    }

    // === Admin Groups ===

    @GetMapping("/groups")
    @PreAuthorize("hasRole('ADMIN')")
    fun listGroups(): ResponseEntity<List<Map<String, Any>>> {
        val groups = adminUserService.listGroups().map { group ->
            mapOf(
                "id" to group.id.toString(),
                "name" to group.name,
                "description" to (group.description ?: "")
            )
        }
        return ResponseEntity.ok(groups)
    }
}

data class AdminUpdateRequest(
    val firstName: String? = null,
    val lastName: String? = null,
    val username: String? = null
)

data class AdminResetPasswordRequest(
    val newPassword: String
)

data class CreateAdminRequest(
    val email: String,
    val password: String,
    val firstName: String? = null,
    val lastName: String? = null,
    val groupNames: List<String> = emptyList()
)

data class UpdateAdminRequest(
    val firstName: String? = null,
    val lastName: String? = null,
    val username: String? = null,
    val groupNames: List<String>? = null
)
