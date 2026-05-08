package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*

@Entity
@Table(name = "admin_groups")
class AdminGroupEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column(nullable = false, unique = true, length = 100)
    val name: String,

    @Column(length = 255)
    val description: String? = null
)
