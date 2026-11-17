package io.github.maignardi.maigshield.core.model

data class ScanReport(
    val threats: List<Threat>,
    val scannedAt: Long = System.currentTimeMillis()
) {
    val isCompromised: Boolean
        get() = threats.any { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH }
}
