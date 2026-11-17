package io.github.maignardi.maigshield.core.policy

import io.github.maignardi.maigshield.core.model.RiskLevel
import io.github.maignardi.maigshield.core.model.SecurityAction
import io.github.maignardi.maigshield.core.model.SecurityAssessment
import io.github.maignardi.maigshield.core.model.SensitiveOperation
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import kotlin.math.min

class PolicyEngine {

    fun evaluate(findings: List<Threat>, executionTimeMs: Long = 0L): SecurityAssessment {
        val score = calculateRiskScore(findings)
        val level = determineRiskLevel(score, findings)
        val action = determineRecommendedAction(level, findings)

        return SecurityAssessment(
            riskScore = score,
            riskLevel = level,
            findings = findings,
            recommendedAction = action,
            executionTimeMs = executionTimeMs
        )
    }

    fun evaluateForOperation(
        findings: List<Threat>,
        operation: SensitiveOperation,
        executionTimeMs: Long = 0L
    ): SecurityAssessment {
        val baseAssessment = evaluate(findings, executionTimeMs)

        // For high-value transactions like PIX or Bank Transfers, adjust sensitivity
        val isHighValueOperation = when (operation) {
            SensitiveOperation.PIX_TRANSFER,
            SensitiveOperation.BANK_TRANSFER,
            SensitiveOperation.WITHDRAWAL_OPERATION,
            SensitiveOperation.PAYMENT_AUTHORIZATION -> true
            else -> false
        }

        val recommendedAction = if (isHighValueOperation) {
            when (baseAssessment.riskLevel) {
                RiskLevel.CRITICAL -> SecurityAction.BLOCK_OPERATION
                RiskLevel.HIGH -> SecurityAction.RESTRICT_SENSITIVE_OPERATION
                RiskLevel.MEDIUM -> SecurityAction.REQUIRE_ADDITIONAL_VERIFICATION
                RiskLevel.LOW -> SecurityAction.MONITOR
                RiskLevel.NORMAL -> SecurityAction.ALLOW
            }
        } else {
            baseAssessment.recommendedAction
        }

        return baseAssessment.copy(recommendedAction = recommendedAction)
    }

    private fun calculateRiskScore(findings: List<Threat>): Int {
        if (findings.isEmpty()) return 0

        var total = 0
        for (threat in findings) {
            total += when (threat.severity) {
                Severity.CRITICAL -> 50
                Severity.HIGH -> 30
                Severity.MEDIUM -> 15
                Severity.LOW -> 5
                Severity.INFO -> 1
            }
        }
        return min(total, 100)
    }

    private fun determineRiskLevel(score: Int, findings: List<Threat>): RiskLevel {
        val hasCritical = findings.any { it.severity == Severity.CRITICAL }
        val hasHigh = findings.any { it.severity == Severity.HIGH }

        return when {
            hasCritical || score >= 75 -> RiskLevel.CRITICAL
            hasHigh || score >= 50 -> RiskLevel.HIGH
            score >= 25 -> RiskLevel.MEDIUM
            score > 0 -> RiskLevel.LOW
            else -> RiskLevel.NORMAL
        }
    }

    private fun determineRecommendedAction(level: RiskLevel, findings: List<Threat>): SecurityAction {
        return when (level) {
            RiskLevel.CRITICAL -> SecurityAction.BLOCK_OPERATION
            RiskLevel.HIGH -> SecurityAction.RESTRICT_SENSITIVE_OPERATION
            RiskLevel.MEDIUM -> SecurityAction.REQUIRE_ADDITIONAL_VERIFICATION
            RiskLevel.LOW -> SecurityAction.MONITOR
            RiskLevel.NORMAL -> SecurityAction.ALLOW
        }
    }
}
