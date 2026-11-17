package com.maigshield.sdk.internal.screen

import android.view.ActionMode
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.SearchEvent
import android.view.View
import android.view.Window
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import com.maigshield.sdk.internal.NativeBridge

internal class ShieldWindowCallback(
    private val delegate: Window.Callback?,
    private val threatMonitor: ScreenThreatMonitor
) : Window.Callback {

    override fun dispatchTouchEvent(event: MotionEvent?): Boolean {
        if (event != null) {
            // Check tapjacking indicators (obscured windows)
            val flags = event.flags
            val isObscured = (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
            val isPartiallyObscured = (flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0

            if (isObscured || isPartiallyObscured) {
                threatMonitor.reportTapjacking()
            }

            // Check synthetic touch indicators (scripted clicks, virtual injectors)
            val deviceId = event.deviceId
            val pressure = event.pressure
            val size = event.size
            val touchMajor = event.touchMajor
            val touchMinor = event.touchMinor

            if (deviceId <= 0 || (pressure <= 0.001f && event.action == MotionEvent.ACTION_DOWN) ||
                (size <= 0.001f && touchMajor <= 0.001f)
            ) {
                threatMonitor.reportSyntheticTouch()
            }

            // Dispatch to native biometrics engine
            try {
                when (event.actionMasked) {
                    MotionEvent.ACTION_DOWN -> {
                        NativeBridge.nativeOnTouchDown(
                            event.x,
                            event.y,
                            pressure,
                            size,
                            touchMajor,
                            touchMinor,
                            deviceId
                        )
                    }
                    MotionEvent.ACTION_MOVE -> {
                        NativeBridge.nativeOnTouchMove(
                            event.x,
                            event.y,
                            pressure,
                            size,
                            touchMajor,
                            touchMinor
                        )
                    }
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                        NativeBridge.nativeOnTouchUp(event.x, event.y)
                    }
                }
            } catch (_: Throwable) {
                // Fail-safe protection against native interruptions
            }
        }

        return delegate?.dispatchTouchEvent(event) ?: false
    }

    override fun dispatchKeyEvent(event: KeyEvent?): Boolean =
        delegate?.dispatchKeyEvent(event) ?: false

    override fun dispatchKeyShortcutEvent(event: KeyEvent?): Boolean =
        delegate?.dispatchKeyShortcutEvent(event) ?: false

    override fun dispatchTrackballEvent(event: MotionEvent?): Boolean =
        delegate?.dispatchTrackballEvent(event) ?: false

    override fun dispatchGenericMotionEvent(event: MotionEvent?): Boolean =
        delegate?.dispatchGenericMotionEvent(event) ?: false

    override fun dispatchPopulateAccessibilityEvent(event: AccessibilityEvent?): Boolean =
        delegate?.dispatchPopulateAccessibilityEvent(event) ?: false

    override fun onCreatePanelView(featureId: Int): View? =
        delegate?.onCreatePanelView(featureId)

    override fun onCreatePanelMenu(featureId: Int, menu: Menu): Boolean =
        delegate?.onCreatePanelMenu(featureId, menu) ?: false

    override fun onPreparePanel(featureId: Int, view: View?, menu: Menu): Boolean =
        delegate?.onPreparePanel(featureId, view, menu) ?: false

    override fun onMenuOpened(featureId: Int, menu: Menu): Boolean =
        delegate?.onMenuOpened(featureId, menu) ?: false

    override fun onMenuItemSelected(featureId: Int, item: MenuItem): Boolean =
        delegate?.onMenuItemSelected(featureId, item) ?: false

    override fun onWindowAttributesChanged(attrs: WindowManager.LayoutParams?) {
        delegate?.onWindowAttributesChanged(attrs)
    }

    override fun onContentChanged() {
        delegate?.onContentChanged()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        delegate?.onWindowFocusChanged(hasFocus)
    }

    override fun onAttachedToWindow() {
        delegate?.onAttachedToWindow()
    }

    override fun onDetachedFromWindow() {
        delegate?.onDetachedFromWindow()
    }

    override fun onPanelClosed(featureId: Int, menu: Menu) {
        delegate?.onPanelClosed(featureId, menu)
    }

    override fun onSearchRequested(): Boolean =
        delegate?.onSearchRequested() ?: false

    override fun onSearchRequested(searchEvent: SearchEvent?): Boolean =
        delegate?.onSearchRequested(searchEvent) ?: false

    override fun onWindowStartingActionMode(callback: ActionMode.Callback?): ActionMode? =
        delegate?.onWindowStartingActionMode(callback)

    override fun onWindowStartingActionMode(callback: ActionMode.Callback?, type: Int): ActionMode? =
        delegate?.onWindowStartingActionMode(callback, type)

    override fun onActionModeStarted(mode: ActionMode?) {
        delegate?.onActionModeStarted(mode)
    }

    override fun onActionModeFinished(mode: ActionMode?) {
        delegate?.onActionModeFinished(mode)
    }
}
