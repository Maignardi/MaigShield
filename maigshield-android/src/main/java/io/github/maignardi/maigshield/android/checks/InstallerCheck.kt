package io.github.maignardi.maigshield.android.checks

import android.content.Context
import android.os.Build
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat

class InstallerCheck(
    private val context: Context,
    private val trustedInstallers: List<String> = DEFAULT_TRUSTED_INSTALLERS,
    private val allowSideloading: Boolean = true
) : SecurityCheck {

    override val id: String = "INSTALLER_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val installerPackage = getInstallerPackageName(context)

            if (installerPackage == null) {
                if (!allowSideloading) {
                    return CheckResult.Compromised(
                        Threat(
                            id = id,
                            name = "Sideloaded Application",
                            description = "Application was installed manually (sideloaded / ADB) rather than via an official app store.",
                            severity = Severity.LOW,
                            details = mapOf("installer" to "unknown/sideloaded")
                        )
                    )
                }
            } else if (trustedInstallers.isNotEmpty() && !trustedInstallers.contains(installerPackage)) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Untrusted Installer Source",
                        description = "Application was installed from an untrusted source: $installerPackage.",
                        severity = Severity.MEDIUM,
                        details = mapOf("installer" to installerPackage)
                    )
                )
            }

            CheckResult.Safe(id)
        } catch (e: Exception) {
            CheckResult.Error(id, e)
        }
    }

    companion object {
        val DEFAULT_TRUSTED_INSTALLERS = listOf(
            "com.android.vending",           // Google Play Store
            "com.google.android.feedback",   // Google Play
            "com.amazon.venezia",            // Amazon Appstore
            "com.sec.android.app.samsungapps"// Samsung Galaxy Store
        )

        fun getInstallerPackageName(context: Context): String? {
            val pm = context.packageManager
            val packageName = context.packageName

            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val info = pm.getInstallSourceInfo(packageName)
                    info.installingPackageName ?: info.initiatingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(packageName)
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}
