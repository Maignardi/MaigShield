package io.github.maignardi.maigshield.android.checks

import android.os.Build
import io.github.maignardi.maigshield.core.check.SecurityCheck
import io.github.maignardi.maigshield.core.model.CheckResult
import io.github.maignardi.maigshield.core.model.Severity
import io.github.maignardi.maigshield.core.model.Threat
import java.io.File
import java.util.Locale

class EmulatorCheck : SecurityCheck {

    override val id: String = "EMULATOR_CHECK"

    override suspend fun execute(): CheckResult {
        return try {
            val indicators = mutableListOf<String>()

            // 1. Hardware and Build properties check
            val buildRating = checkBuildProperties()
            if (buildRating.first) {
                indicators.add(buildRating.second)
            }

            // 2. Emulator file artifacts check
            val fileIndicator = checkEmulatorFiles()
            if (fileIndicator != null) {
                indicators.add("emulator-file:$fileIndicator")
            }

            if (indicators.isNotEmpty()) {
                return CheckResult.Compromised(
                    Threat(
                        id = id,
                        name = "Emulator / Virtual Environment Detected",
                        description = "Application is running inside an Android emulator or virtual machine.",
                        severity = Severity.MEDIUM,
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

    private fun checkBuildProperties(): Pair<Boolean, String> {
        val fingerprint = Build.FINGERPRINT?.lowercase(Locale.ROOT) ?: ""
        val model = Build.MODEL?.lowercase(Locale.ROOT) ?: ""
        val manufacturer = Build.MANUFACTURER?.lowercase(Locale.ROOT) ?: ""
        val hardware = Build.HARDWARE?.lowercase(Locale.ROOT) ?: ""
        val product = Build.PRODUCT?.lowercase(Locale.ROOT) ?: ""
        val brand = Build.BRAND?.lowercase(Locale.ROOT) ?: ""
        val device = Build.DEVICE.lowercase(Locale.ROOT)

        val isGeneric = fingerprint.startsWith("generic") || fingerprint.startsWith("unknown")
        val isGoogleAosp = model.contains("google_sdk") || model.contains("droid4x") || model.contains("emulator") || model.contains("android sdk built for x86")
        val isHardwareQemu = hardware.contains("goldfish") || hardware.contains("ranchu") || hardware.contains("vbox86")
        val isProductGeneric = product.contains("sdk") || product.contains("google_sdk") || product.contains("sdk_x86") || product.contains("vbox86p") || product.contains("emulator")
        val isBrandGeneric = brand.startsWith("generic") || brand.startsWith("android")

        val matchDetails = mutableListOf<String>()
        if (isGeneric) matchDetails.add("fingerprint:$fingerprint")
        if (isGoogleAosp) matchDetails.add("model:$model")
        if (isHardwareQemu) matchDetails.add("hardware:$hardware")
        if (isProductGeneric) matchDetails.add("product:$product")

        val isEmulator = (isGeneric || isGoogleAosp || isHardwareQemu || isProductGeneric) &&
                (manufacturer.contains("genymotion") || manufacturer.contains("unknown") || hardware.contains("goldfish") || hardware.contains("ranchu") || model.contains("emulator") || product.contains("sdk"))

        return Pair(isEmulator, matchDetails.joinToString("|"))
    }

    private fun checkEmulatorFiles(): String? {
        val emulatorFiles = arrayOf(
            "/dev/qemu_pipe",
            "/dev/socket/qemud",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )

        for (path in emulatorFiles) {
            if (File(path).exists()) {
                return path
            }
        }
        return null
    }
}
