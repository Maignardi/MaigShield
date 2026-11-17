package io.github.maignardi.maigshield.core.model

data class SecurityEvent(
    val type: String,
    val threat: Threat,
    val timestamp: Long = System.currentTimeMillis()
)
