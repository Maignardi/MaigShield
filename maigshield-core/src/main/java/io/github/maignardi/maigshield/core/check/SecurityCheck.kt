package io.github.maignardi.maigshield.core.check

import io.github.maignardi.maigshield.core.model.CheckResult

interface SecurityCheck {
    val id: String
    suspend fun execute(): CheckResult
}
