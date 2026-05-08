package com.zhouij.authplatform.iam.domain

import jakarta.persistence.*
import java.util.UUID

@Entity
@Table(name = "admin_group_members")
@IdClass(AdminGroupMemberId::class)
class AdminGroupMemberEntity(
    @Id
    @Column(name = "admin_user_id")
    val adminUserId: UUID,

    @Id
    @Column(name = "group_id")
    val groupId: Long
)

data class AdminGroupMemberId(
    val adminUserId: UUID = UUID.randomUUID(),
    val groupId: Long = 0
) : java.io.Serializable
