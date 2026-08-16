package com.zhouij.authplatform.iam.service

import org.slf4j.LoggerFactory
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.mail.SimpleMailMessage
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.stereotype.Service

/**
 * Sends transactional email (password reset, verification).
 *
 * - `email.enabled=true` + SMTP settings (`spring.mail.*`) → real email.
 * - `email.enabled=false` (default for local dev) → the message is logged
 *   instead of sent, so flows remain testable without a mail server.
 */
@Service
class EmailService(
    @param:Value("\${email.enabled:false}") private val enabled: Boolean,
    @param:Value("\${email.from:no-reply@localhost}") private val from: String,
    private val javaMailSender: ObjectProvider<JavaMailSender>
) {
    private val logger = LoggerFactory.getLogger(EmailService::class.java)

    fun sendPasswordReset(to: String, userType: String, resetLink: String) {
        send(
            to = to,
            subject = "Reset your password",
            body = """
                A password reset was requested for your $userType account.

                Reset link (valid for 15 minutes):
                $resetLink

                If you did not request this, you can ignore this email.
            """.trimIndent()
        )
    }

    fun sendVerification(to: String, verificationLink: String) {
        send(
            to = to,
            subject = "Verify your email address",
            body = """
                Welcome to the auth platform!

                Verify your email address (valid for 24 hours):
                $verificationLink

                If you did not create an account, you can ignore this email.
            """.trimIndent()
        )
    }

    private fun send(to: String, subject: String, body: String) {
        if (!enabled) {
            logger.info("EMAIL DISABLED — would send to {}: subject='{}' body={}", to, subject, body.replace('\n', ' '))
            return
        }
        val sender = javaMailSender.ifAvailable ?: run {
            logger.error(
                "email.enabled=true but no SMTP host is configured (spring.mail.host) — " +
                    "refusing to silently drop the message to {}",
                to
            )
            return
        }
        try {
            val message = SimpleMailMessage()
            message.setFrom(from)
            message.setTo(to)
            message.setSubject(subject)
            message.setText(body)
            sender.send(message)
            logger.info("Email sent to {} (subject: {})", to, subject)
        } catch (e: Exception) {
            logger.error("Failed to send email to {}", to, e)
        }
    }
}
