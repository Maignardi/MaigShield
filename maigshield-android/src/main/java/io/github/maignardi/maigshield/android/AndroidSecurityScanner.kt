package io.github.maignardi.maigshield.android

import android.content.Context
import io.github.maignardi.maigshield.android.checks.DebuggerCheck
import io.github.maignardi.maigshield.android.checks.EmulatorCheck
import io.github.maignardi.maigshield.android.checks.HookingCheck
import io.github.maignardi.maigshield.android.checks.InstallerCheck
import io.github.maignardi.maigshield.android.checks.RootCheck
import io.github.maignardi.maigshield.android.checks.SignatureCheck
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.ScanReport
import io.github.maignardi.maigshield.core.model.Threat

class AndroidSecurityScanner(
    private val context: Context,
    private val customChecks: List<SecurityCheck> = emptyList(),
    private val expectedSignatureHashes: List<String> = emptyList(),
    private val allowDebuggable: Boolean = false,
    private val checkRoot: Boolean = true,
    private val checkEmulator: Boolean = true,
    private val checkHooking: Boolean = true,
    private val checkInstaller: Boolean = true,
    private val allowSideloading: Boolean = true,
    private val trustedInstallers: List<String> = emptyList()
) {
    private val defaultChecks: List<SecurityCheck> by lazy {
        val list = mutableListOf<SecurityCheck>()
        list.add(SignatureCheck(context, expectedSignatureHashes))
        list.add(DebuggerCheck(context, allowDebuggable))
        if (checkRoot) list.add(RootCheck(context))
        if (checkEmulator) list.add(EmulatorCheck())
        if (checkHooking) list.add(HookingCheck())
        if (checkInstaller) {
            val installers = if (trustedInstallers.isEmpty()) InstallerCheck.DEFAULT_TRUSTED_INSTALLERS else trustedInstallers
            list.add(InstallerCheck(context, installers, allowSideloading))
        }
        list
    }

    suspend fun scan(): ScanReport {
        val allChecks = defaultChecks + customChecks
        val threats = mutableListOf<Threat>()

        for (check in allChecks) {
            when (val result = check.execute()) {
                is CheckResult.Compromised -> threats.add(result.threat)
                is CheckResult.Safe -> { /* Clean */ }
                is CheckResult.Error -> {
                    // Ignore or record error
                }
            }
        }

        return ScanReport(threats = threats)
    }
}
