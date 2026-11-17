package io.github.maignardi.maigshield.android.checks

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat

class DebuggerCheck(
    private val context: Context,
    private val allowDebuggableBuild: Boolean = false
) : SecurityCheck {

    override val id: String = "DEBUGGER_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val isDebuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
            val isDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

            if (isDebuggerAttached) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Debugger Attached",
                        description = "An active debugger is attached to the process.",
                        severity = Severity.HIGH,
                        details = mapOf("isDebuggerConnected" to "true")
                    )
                )
            }

            if (isDebuggable && !allowDebuggableBuild) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Debuggable Application",
                        description = "Application is compiled in debuggable mode.",
                        severity = Severity.MEDIUM,
                        details = mapOf("FLAG_DEBUGGABLE" to "true")
                    )
                )
            }

            CheckResult.Safe(id)
        } catch (e: Exception) {
            CheckResult.Error(id, e)
        }
    }
}
