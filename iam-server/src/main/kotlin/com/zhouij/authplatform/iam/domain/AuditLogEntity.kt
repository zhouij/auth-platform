package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "audit_log")
class AuditLogEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column(name = "occurred_at", nullable = false, updatable = false)
    val occurredAt: Instant = Instant.now(),

    @Column(name = "actor_type", length = 50)
    var actorType: String? = null,

    @Column(name = "actor_id", length = 255)
    var actorId: String? = null,

    @Column(nullable = false, length = 100)
    var action: String,

    @Column(length = 255)
    var target: String? = null,

    @Column(name = "ip_address", length = 45)
    var ipAddress: String? = null,

    @Column(nullable = false, length = 20)
    var outcome: String,

    @Column(length = 1000)
    var detail: String? = null
) {
    enum class Outcome { SUCCESS, FAILURE }
}
