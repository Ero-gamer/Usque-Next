package io.github.georgexie2333.usque

import io.flutter.plugin.common.MethodChannel

/** Keeps onboarding notification-only and defers VPN preparation until connection confirmation. */
internal class OnboardingPermissionCoordinator(
    private val host: Host,
) {
    interface Host {
        fun vpnGranted(): Boolean

        fun notificationState(): String

        fun launchVpnConfirmation()

        fun launchVpn()

        fun launchNotification()
    }

    private enum class Dialog { NONE, CONFIRMATION, VPN, NOTIFICATION }

    private data class Pending(
        val result: MethodChannel.Result,
        val requireVpn: Boolean,
        val connect: (() -> Unit)?,
    )

    private var pending: Pending? = null
    private var dialog = Dialog.NONE
    private var destroyed = false

    // Only system dialogs survive Activity recreation. The local confirmation is dismissed.
    fun outstandingDialog(): String? = dialog.takeIf { it == Dialog.VPN || it == Dialog.NOTIFICATION }?.name

    fun restoreOutstandingDialog(value: String?) {
        if (pending == null && dialog == Dialog.NONE) {
            dialog = Dialog.entries.firstOrNull { it.name == value && (it == Dialog.VPN || it == Dialog.NOTIFICATION) }
                ?: Dialog.NONE
        }
    }

    // VpnService.prepare is not a read-only permission query: it can revoke another VPN.
    fun status(): Map<String, Any> = mapOf("notification" to notificationState())

    private fun notificationState(): String = runCatching { host.notificationState() }.getOrDefault("notGranted")

    fun prepare(result: MethodChannel.Result) = begin(result, false, null)

    fun connect(
        result: MethodChannel.Result,
        requireVpn: Boolean,
        continuation: () -> Unit,
    ) = begin(result, requireVpn, continuation)

    private fun begin(
        result: MethodChannel.Result,
        requireVpn: Boolean,
        continuation: (() -> Unit)?,
    ) {
        if (destroyed) {
            result.error("VPN_PERMISSION_CANCELLED", "The Android UI closed.", null)
            return
        }
        if (pending != null || dialog != Dialog.NONE) {
            result.error("VPN_PERMISSION_IN_PROGRESS", "Another permission request is in progress.", null)
            return
        }
        pending = Pending(result, requireVpn, continuation)
        try {
            if (requireVpn) {
                dialog = Dialog.CONFIRMATION
                host.launchVpnConfirmation()
            } else if (continuation == null) {
                requestNotification()
            } else {
                complete()
            }
        } catch (_: Exception) {
            dialog = Dialog.NONE
            val request = pending.also { pending = null }
            request?.result?.error("VPN_PERMISSION_LAUNCH_FAILED", "Android could not request VPN permission.", null)
        }
    }

    fun finishConfirmation(confirmed: Boolean) {
        if (dialog != Dialog.CONFIRMATION || destroyed) return
        dialog = Dialog.NONE
        if (pending == null) return
        if (!confirmed) {
            cancel("VPN_PERMISSION_CANCELLED", "The VPN connection was cancelled.")
            return
        }
        try {
            if (host.vpnGranted()) {
                complete()
            } else {
                dialog = Dialog.VPN
                host.launchVpn()
            }
        } catch (_: Exception) {
            dialog = Dialog.NONE
            cancel("VPN_PERMISSION_LAUNCH_FAILED", "Android could not request VPN permission.")
        }
    }

    fun finishVpn(granted: Boolean) {
        if (dialog != Dialog.VPN || destroyed) return
        dialog = Dialog.NONE
        if (pending == null) return
        try {
            if (!granted || !host.vpnGranted()) {
                complete(vpnDenied = true)
            } else {
                complete()
            }
        } catch (_: Exception) {
            val request = pending.also { pending = null }
            request?.result?.error("VPN_PERMISSION_LAUNCH_FAILED", "Android could not verify VPN permission.", null)
        }
    }

    private fun requestNotification() {
        if (pending == null) return
        if (notificationState() == "notRequested") {
            dialog = Dialog.NOTIFICATION
            try {
                host.launchNotification()
            } catch (_: Exception) {
                dialog = Dialog.NONE
                complete()
            }
        } else {
            complete()
        }
    }

    fun finishNotification() {
        if (dialog != Dialog.NOTIFICATION || destroyed) return
        dialog = Dialog.NONE
        complete()
    }

    private fun complete(vpnDenied: Boolean = false) {
        val request = pending.also { pending = null } ?: return
        if (request.connect != null && !request.requireVpn) {
            request.connect.invoke()
            return
        }
        try {
            if (request.connect == null) {
                request.result.success(status())
            } else if (request.requireVpn && (vpnDenied || !host.vpnGranted())) {
                request.result.error("VPN_PERMISSION_DENIED", "VPN permission was not granted.", null)
            } else {
                request.connect.invoke()
            }
        } catch (_: Exception) {
            request.result.error("VPN_PERMISSION_LAUNCH_FAILED", "Android could not verify permissions.", null)
        }
    }

    fun cancelConnection(
        code: String,
        message: String,
    ) {
        if (pending?.connect == null) return
        cancel(code, message)
    }

    private fun cancel(
        code: String,
        message: String,
    ) {
        val request = pending.also { pending = null } ?: return
        // Keep the dialog occupied: ActivityResult callbacks cannot identify an old request.
        request.result.error(code, message, null)
    }

    fun destroy() {
        destroyed = true
        cancel("VPN_PERMISSION_CANCELLED", "The Android UI closed before permissions were granted.")
    }
}
