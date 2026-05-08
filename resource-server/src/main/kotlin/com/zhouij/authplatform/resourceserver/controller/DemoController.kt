package com.zhouij.authplatform.resourceserver.controller

import com.zhouij.authplatform.resourceserver.domain.UserResourceEntity
import com.zhouij.authplatform.resourceserver.repository.UserResourceRepository
import com.zhouij.authplatform.resourceserver.service.AuthorizationChecker
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1")
class DemoController(
    private val authorizationChecker: AuthorizationChecker,
    private val resourceRepository: UserResourceRepository
) {

    @GetMapping("/public/status")
    fun publicStatus(): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(
            mapOf(
                "status" to "ok",
                "service" to "resource-server",
                "message" to "Public endpoint — no authentication required"
            )
        )
    }

    @GetMapping("/me")
    fun me(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(
            mapOf(
                "subject" to jwt.subject,
                "userType" to (jwt.claims["user_type"] ?: "unknown"),
                "scopes" to (jwt.claims["scope"] ?: "none"),
                "roles" to (jwt.claims["roles"] ?: emptyList<String>())
            )
        )
    }

    @GetMapping("/resources")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    fun listResources(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<List<Map<String, Any>>> {
        val resources = resourceRepository.findAll().map { it.toMap() }
        return ResponseEntity.ok(resources)
    }

    @GetMapping("/resources/{id}")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    fun getResource(
        @PathVariable id: java.util.UUID,
        @AuthenticationPrincipal jwt: Jwt
    ): ResponseEntity<Any> {
        val resource = resourceRepository.findById(id).orElse(null)
            ?: return ResponseEntity.notFound().build()

        val requesterId = jwt.subject
        val role = extractRole(jwt)

        if (!authorizationChecker.canRead(requesterId, resource.ownerSubject, role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "Access denied"))
        }

        return ResponseEntity.ok(resource.toMap())
    }

    @PostMapping("/resources")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    fun createResource(
        @RequestBody request: CreateResourceRequest,
        @AuthenticationPrincipal jwt: Jwt
    ): ResponseEntity<Map<String, Any>> {
        val resource = resourceRepository.save(
            UserResourceEntity(
                ownerSubject = jwt.subject,
                name = request.name,
                data = request.data
            )
        )
        return ResponseEntity.status(HttpStatus.CREATED).body(resource.toMap())
    }

    @PutMapping("/resources/{id}")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    fun updateResource(
        @PathVariable id: java.util.UUID,
        @RequestBody request: UpdateResourceRequest,
        @AuthenticationPrincipal jwt: Jwt
    ): ResponseEntity<Any> {
        val resource = resourceRepository.findById(id).orElse(null)
            ?: return ResponseEntity.notFound().build()

        val role = extractRole(jwt)
        if (!authorizationChecker.canWrite(jwt.subject, resource.ownerSubject, role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "Access denied"))
        }

        request.name?.let { resource.name = it }
        request.data?.let { resource.data = it }
        resource.updatedAt = java.time.Instant.now()
        resourceRepository.save(resource)

        return ResponseEntity.ok(resource.toMap())
    }

    @DeleteMapping("/resources/{id}")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    fun deleteResource(
        @PathVariable id: java.util.UUID,
        @AuthenticationPrincipal jwt: Jwt
    ): ResponseEntity<Any> {
        val resource = resourceRepository.findById(id).orElse(null)
            ?: return ResponseEntity.notFound().build()

        val role = extractRole(jwt)
        if (!authorizationChecker.canDelete(jwt.subject, resource.ownerSubject, role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mapOf("error" to "Access denied"))
        }

        resourceRepository.delete(resource)
        return ResponseEntity.noContent().build()
    }

    @GetMapping("/admin/resources")
    @PreAuthorize("hasRole('ADMIN')")
    fun adminListAllResources(): ResponseEntity<List<Map<String, Any>>> {
        return ResponseEntity.ok(resourceRepository.findAll().map { it.toMap() })
    }

    @GetMapping("/whoami")
    fun whoAmI(@AuthenticationPrincipal jwt: Jwt): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(
            mapOf(
                "subject" to jwt.subject,
                "claims" to jwt.claims,
                "scopes" to (jwt.claims["scope"] ?: "none"),
                "roles" to (jwt.claims["roles"] ?: emptyList<String>()),
                "userType" to (jwt.claims["user_type"] ?: "unknown"),
                "issuedAt" to (jwt.issuedAt?.toString() ?: ""),
                "expiresAt" to (jwt.expiresAt?.toString() ?: "")
            )
        )
    }

    private fun extractRole(jwt: Jwt): String? {
        @Suppress("UNCHECKED_CAST")
        val roles = jwt.claims["roles"] as? List<String>
        return roles?.firstOrNull()
    }

    private fun UserResourceEntity.toMap(): Map<String, Any> = mapOf(
        "id" to (id?.toString() ?: ""),
        "ownerSubject" to ownerSubject,
        "name" to name,
        "data" to (data ?: ""),
        "createdAt" to createdAt.toString(),
        "updatedAt" to updatedAt.toString()
    )
}

data class CreateResourceRequest(
    val name: String,
    val data: String? = null
)

data class UpdateResourceRequest(
    val name: String? = null,
    val data: String? = null
)
