package com.maigshield.sdk.internal.screen

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Bundle
import android.view.Display
import android.view.WindowManager
import android.view.accessibility.AccessibilityManager
import java.util.concurrent.atomic.AtomicLong

internal class ScreenThreatMonitor(
    private val context: Context,
    private val enableAccessibilityCheck: Boolean = true,
    private val enableScreenMirrorCheck: Boolean = true,
    private val enableTapjackingCheck: Boolean = true
) : Application.ActivityLifecycleCallbacks {

    private val accumulatedFlags = AtomicLong(0L)
    private val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
    private val accessibilityManager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager

    private val displayListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) {
            checkActiveDisplays()
        }

        override fun onDisplayRemoved(displayId: Int) {
            checkActiveDisplays()
        }

        override fun onDisplayChanged(displayId: Int) {
            checkActiveDisplays()
        }
    }

    init {
        if (enableScreenMirrorCheck) {
            displayManager?.registerDisplayListener(displayListener, null)
            checkActiveDisplays()
        }
        if (enableAccessibilityCheck) {
            checkAccessibilityAbuse()
        }
    }

    fun reportTapjacking() {
        if (enableTapjackingCheck) {
            accumulatedFlags.updateAndGet { it or FLAG_TAPJACKING_DETECTED }
        }
    }

    fun reportSyntheticTouch() {
        accumulatedFlags.updateAndGet { it or FLAG_SYNTHETIC_TOUCH_DETECTED }
    }

    fun checkAccessibilityAbuse(): Boolean {
        if (!enableAccessibilityCheck) return false
        val mgr = accessibilityManager ?: return false

        try {
            val enabledServices = mgr.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            val pm = context.packageManager

            for (service in enabledServices) {
                val serviceInfo = service.resolveInfo?.serviceInfo ?: continue
                val pkgName = serviceInfo.packageName

                // Skip known trusted system packages
                if (isSystemPackage(pm, pkgName)) {
                    continue
                }

                val capabilities = service.capabilities
                val canStealWindow = (capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0
                val canPerformGestures = (capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES) != 0

                if (canStealWindow || canPerformGestures) {
                    accumulatedFlags.updateAndGet { it or FLAG_ACCESSIBILITY_ABUSE }
                    return true
                }
            }
        } catch (_: Exception) {
            // Keep fail-safe
        }
        return false
    }

    fun checkActiveDisplays(): Boolean {
        if (!enableScreenMirrorCheck) return false
        val dm = displayManager ?: return false

        try {
            val displays = dm.displays
            for (display in displays) {
                if (display.displayId == Display.DEFAULT_DISPLAY) {
                    continue
                }

                val flags = display.flags
                val isPresentation = (flags and Display.FLAG_PRESENTATION) != 0
                val isPublic = (flags and Display.FLAG_PRIVATE) == 0
                val name = display.name.lowercase()

                val isVirtual = name.contains("virtual") ||
                        name.contains("overlay") ||
                        name.contains("mediaprojection") ||
                        name.contains("cast") ||
                        name.contains("miracast") ||
                        name.contains("screen")

                if (isPresentation || isPublic || isVirtual) {
                    accumulatedFlags.updateAndGet { it or FLAG_SCREEN_MIRRORING }
                    return true
                }
            }
        } catch (_: Exception) {
            // Keep fail-safe
        }
        return false
    }

    private fun isSystemPackage(pm: PackageManager, packageName: String): Boolean {
        return try {
            val appInfo = pm.getApplicationInfo(packageName, 0)
            (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 ||
                    packageName.startsWith("com.google.android.") ||
                    packageName.startsWith("com.android.")
        } catch (_: Exception) {
            false
        }
    }

    fun getThreatFlags(): Long {
        checkAccessibilityAbuse()
        checkActiveDisplays()
        return accumulatedFlags.get()
    }

    // ActivityLifecycleCallbacks injection for ShieldWindowCallback
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
        injectWindowCallback(activity)
    }

    override fun onActivityStarted(activity: Activity) {
        injectWindowCallback(activity)
    }

    override fun onActivityResumed(activity: Activity) {
        injectWindowCallback(activity)
    }

    override fun onActivityPaused(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {}

    private fun injectWindowCallback(activity: Activity) {
        val window = activity.window ?: return
        if (enableScreenMirrorCheck) {
            try {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } catch (_: Exception) {}
        }
        val currentCallback = window.callback
        if (currentCallback !is ShieldWindowCallback) {
            window.callback = ShieldWindowCallback(currentCallback, this)
        }
    }

    companion object {
        const val FLAG_ACCESSIBILITY_ABUSE: Long      = 1L shl 16
        const val FLAG_SCREEN_MIRRORING: Long         = 1L shl 17
        const val FLAG_TAPJACKING_DETECTED: Long      = 1L shl 18
        const val FLAG_SYNTHETIC_TOUCH_DETECTED: Long = 1L shl 19
    }
}
