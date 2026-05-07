package com.zhouij.authplatform.resourceserver.service

import org.springframework.stereotype.Service

@Service
class AuthorizationChecker {
    fun canRead(requesterId: String, ownerId: String, role: String?): Boolean =
        requesterId == ownerId || role?.uppercase() in setOf("ADMIN", "USER")

    fun canWrite(requesterId: String, ownerId: String, role: String?): Boolean =
        requesterId == ownerId || role?.uppercase() == "ADMIN"

    fun canDelete(requesterId: String, ownerId: String, role: String?): Boolean =
        requesterId == ownerId || role?.uppercase() == "ADMIN"
}
