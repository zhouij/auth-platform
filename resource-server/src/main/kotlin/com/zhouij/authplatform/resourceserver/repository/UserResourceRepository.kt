package com.zhouij.authplatform.resourceserver.repository

import com.zhouij.authplatform.resourceserver.domain.UserResourceEntity
import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserResourceRepository : JpaRepository<UserResourceEntity, UUID> {
    fun findByOwnerSubject(ownerSubject: String): List<UserResourceEntity>
    fun findByOwnerSubjectAndName(ownerSubject: String, name: String): UserResourceEntity?
}
