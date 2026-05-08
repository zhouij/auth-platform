package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "admin_users")
class AdminUserEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    val id: UUID? = null,

    @Column(nullable = false, length = 255)
    var email: String,

    @Column(length = 100)
    var username: String? = null,

    @Column(nullable = false, length = 255, name = "password_hash")
    var passwordHash: String,

    @Column(name = "first_name", length = 100)
    var firstName: String? = null,

    @Column(name = "last_name", length = 100)
    var lastName: String? = null,

    @Column(nullable = false)
    var enabled: Boolean = true,

    @Column(name = "credentials_changed_at", nullable = false)
    var credentialsChangedAt: Instant = Instant.now(),

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),

    @Column(name = "last_login_at")
    var lastLoginAt: Instant? = null,

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "admin_group_members",
        joinColumns = [JoinColumn(name = "admin_user_id")],
        inverseJoinColumns = [JoinColumn(name = "group_id")]
    )
    var groups: MutableSet<AdminGroupEntity> = mutableSetOf()
)
