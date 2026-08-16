package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.PasswordHistoryEntity
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.util.UUID

interface PasswordHistoryRepository : JpaRepository<PasswordHistoryEntity, Long> {

    @Query(
        "SELECT ph FROM PasswordHistoryEntity ph " +
            "WHERE ph.userId = :userId ORDER BY ph.createdAt DESC"
    )
    fun findRecentForUser(@Param("userId") userId: UUID, pageable: Pageable): List<PasswordHistoryEntity>

    @Query(
        "SELECT ph FROM PasswordHistoryEntity ph " +
            "WHERE ph.adminUserId = :adminUserId ORDER BY ph.createdAt DESC"
    )
    fun findRecentForAdmin(@Param("adminUserId") adminUserId: UUID, pageable: Pageable): List<PasswordHistoryEntity>

    fun deleteByUserId(userId: UUID)
    fun deleteByAdminUserId(adminUserId: UUID)
}
