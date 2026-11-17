package io.github.maignardi.maigshield.core.model

data class Threat(
    val id: String,
    val name: String,
    val description: String,
    val severity: Severity,
    val details: Map<String, String> = emptyMap()
)
