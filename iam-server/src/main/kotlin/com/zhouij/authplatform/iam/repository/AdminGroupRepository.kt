package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.AdminGroupEntity
import org.springframework.data.jpa.repository.JpaRepository

interface AdminGroupRepository : JpaRepository<AdminGroupEntity, Long> {
    fun findByName(name: String): AdminGroupEntity?
    fun findByNameIn(names: Collection<String>): List<AdminGroupEntity>
}
