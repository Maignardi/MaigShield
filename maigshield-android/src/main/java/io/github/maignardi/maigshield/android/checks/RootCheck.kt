package io.github.maignardi.maigshield.android.checks

import android.content.Context
import android.os.Build
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import java.io.File

class RootCheck(
    private val context: Context
) : SecurityCheck {

    override val id: String = "ROOT_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val detectedIndicators = mutableListOf<String>()

            // 1. Check for test-keys build tags
            if (checkTestKeys()) {
                detectedIndicators.add("test-keys-build")
            }

            // 2. Check for su binaries in system paths
            val suPath = findSuBinary()
            if (suPath != null) {
                detectedIndicators.add("su-binary-found:$suPath")
            }

            // 3. Check for root management packages
            val rootPackage = findRootPackage(context)
            if (rootPackage != null) {
                detectedIndicators.add("root-app-installed:$rootPackage")
            }

            if (detectedIndicators.isNotEmpty()) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Root / Superuser Access Detected",
                        description = "Device appears to be rooted or running custom firmware.",
                        severity = Severity.HIGH,
                        details = mapOf(
                            "indicators" to detectedIndicators.joinToString(",")
                        )
                    )
                )
            }

            CheckResult.Safe(id)
        } catch (e: Exception) {
            CheckResult.Error(id, e)
        }
    }

    private fun checkTestKeys(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun findSuBinary(): String? {
        val commonSuPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        for (path in commonSuPaths) {
            if (File(path).exists()) {
                return path
            }
        }
        return null
    }

    private fun findRootPackage(context: Context): String? {
        val knownRootApps = listOf(
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root"
        )

        val pm = context.packageManager
        for (pkg in knownRootApps) {
            try {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
                return pkg
            } catch (_: Exception) {
                // Package not found
            }
        }
        return null
    }
}
