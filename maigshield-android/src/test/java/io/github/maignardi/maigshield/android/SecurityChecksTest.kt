package io.github.maignardi.maigshield.android

import io.github.maignardi.maigshield.android.checks.EmulatorCheck
import io.github.maignardi.maigshield.android.checks.HookingCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.ScanReport
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityChecksTest {

    @Test
    fun scanReport_isCompromised_returnsTrueForCriticalThreats() {
        val criticalThreat = Threat(
            id = "TEST",
            name = "Test Critical",
            description = "Test threat",
            severity = Severity.CRITICAL
        )
        val report = ScanReport(threats = listOf(criticalThreat))

        assertTrue(report.isCompromised)
    }

    @Test
    fun scanReport_isCompromised_returnsFalseForLowThreats() {
        val lowThreat = Threat(
            id = "TEST",
            name = "Test Low",
            description = "Test low threat",
            severity = Severity.LOW
        )
        val report = ScanReport(threats = listOf(lowThreat))

        assertFalse(report.isCompromised)
    }

    @Test
    fun hookingCheck_executesWithoutException() = runBlocking {
        val check = HookingCheck()
        assertEquals("HOOKING_CHECK", check.id)

        val result = check.execute()
        assertNotNull(result)
        assertTrue(result is CheckResult.Safe || result is CheckResult.Compromised)
    }

    @Test
    fun emulatorCheck_executesWithoutException() = runBlocking {
        val check = EmulatorCheck()
        assertEquals("EMULATOR_CHECK", check.id)

        val result = check.execute()
        assertNotNull(result)
        assertTrue(
            "Expected Safe, Compromised, or Error result",
            result is CheckResult.Safe || result is CheckResult.Compromised || result is CheckResult.Error
        )
    }
}
