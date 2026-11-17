package io.github.maignardi.maigshield.core.model

sealed interface CheckResult {
    data class Safe(val checkId: String) : CheckResult
    data class Compromised(val threat: Threat) : CheckResult
    data class Error(val checkId: String, val throwable: Throwable) : CheckResult
}
