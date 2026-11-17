package io.github.maignardi.maigshield.android.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import java.security.MessageDigest
import java.util.Locale

class SignatureCheck(
    private val context: Context,
    private val expectedSha256Hashes: List<String> = emptyList()
) : SecurityCheck {

    override val id: String = "SIGNATURE_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val currentHashes = getAppSignatureHashes(context)
            if (currentHashes.isEmpty()) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Signature Missing",
                        description = "No APK signing certificate could be retrieved.",
                        severity = Severity.CRITICAL
                    )
                )
            }

            if (expectedSha256Hashes.isNotEmpty()) {
                val formattedExpected = expectedSha256Hashes.map { it.replace(":", "").uppercase(Locale.ROOT) }
                val matches = currentHashes.any { current ->
                    formattedExpected.contains(current.replace(":", "").uppercase(Locale.ROOT))
                }
                if (!matches) {
                    return CheckResult.Compromised(
                        Threat(
                            id = id,
                            name = "APK Signature Mismatch",
                            description = "Application signature SHA-256 does not match expected certificate(s). APK may be tampered.",
                            severity = Severity.CRITICAL,
                            details = mapOf(
                                "detected_hashes" to currentHashes.joinToString(",")
                            )
                        )
                    )
                }
            }

            CheckResult.Safe(id)
        } catch (e: Exception) {
            CheckResult.Error(id, e)
        }
    }

    companion object {
        fun getAppSignatureHashes(context: Context): List<String> {
            val packageManager = context.packageManager
            val packageName = context.packageName

            val signatures: Array<out android.content.pm.Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = packageInfo.signingInfo
                if (signingInfo != null) {
                    if (signingInfo.hasMultipleSigners()) {
                        signingInfo.apkContentsSigners
                    } else {
                        signingInfo.signingCertificateHistory
                    }
                } else null
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES
                )
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures == null) return emptyList()

            return signatures.map { signature ->
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(signature.toByteArray())
                digest.joinToString("") { "%02X".format(it) }
            }
        }
    }
}
