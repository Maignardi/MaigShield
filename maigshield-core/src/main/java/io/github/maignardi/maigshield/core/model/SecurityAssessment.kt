package io.github.maignardi.maigshield.core.model

data class SecurityAssessment(
    val riskScore: Int,
    val riskLevel: RiskLevel,
    val findings: List<Threat>,
    val recommendedAction: SecurityAction,
    val executionTimeMs: Long = 0L,
    val assessedAt: Long = System.currentTimeMillis()
)
