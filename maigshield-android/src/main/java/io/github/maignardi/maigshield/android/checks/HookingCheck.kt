package io.github.maignardi.maigshield.android.checks

import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

class HookingCheck : SecurityCheck {

    override val id: String = "HOOKING_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val indicators = mutableListOf<String>()

            // 1. Check stack trace for Xposed / Frida injection frames
            if (checkStackTrace()) {
                indicators.add("stack-trace-hooking-frame")
            }

            // 2. Check /proc/self/maps for hooked libraries
            val mappedLib = checkProcMaps()
            if (mappedLib != null) {
                indicators.add("proc-maps-lib:$mappedLib")
            }

            if (indicators.isNotEmpty()) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Hooking Framework Detected",
                        description = "Frida, Xposed, or dynamic instrumentation framework detected in memory.",
                        severity = Severity.CRITICAL,
                        details = mapOf(
                            "indicators" to indicators.joinToString(",")
                        )
                    )
                )
            }

            CheckResult.Safe(id)
        } catch (e: Exception) {
            CheckResult.Error(id, e)
        }
    }

    private fun checkStackTrace(): Boolean {
        val stackTrace = Exception().stackTrace
        for (element in stackTrace) {
            val className = element.className
            if (className.contains("de.robv.android.xposed.XposedBridge") ||
                className.contains("com.saurik.substrate") ||
                className.contains("com.elderdriver.riru") ||
                className.contains("io.github.lsposed")
            ) {
                return true
            }
        }
        return false
    }

    private fun checkProcMaps(): String? {
        val mapsFile = File("/proc/self/maps")
        if (!mapsFile.exists()) return null

        try {
            BufferedReader(FileReader(mapsFile)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val currentLine = line ?: continue
                    if (currentLine.contains("frida") ||
                        currentLine.contains("xposed") ||
                        currentLine.contains("substrate") ||
                        currentLine.contains("gadget")
                    ) {
                        return currentLine.trim()
                    }
                }
            }
        } catch (_: Exception) {
            // Memory inspection restricted
        }
        return null
    }
}
