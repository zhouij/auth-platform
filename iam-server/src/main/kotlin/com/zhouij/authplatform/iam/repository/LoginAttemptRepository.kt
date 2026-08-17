package com.zhouij.authplatform.iam.repository

import com.zhouij.authplatform.iam.domain.LoginAttemptEntity
import org.springframework.data.jpa.repository.JpaRepository

interface LoginAttemptRepository : JpaRepository<LoginAttemptEntity, String>
