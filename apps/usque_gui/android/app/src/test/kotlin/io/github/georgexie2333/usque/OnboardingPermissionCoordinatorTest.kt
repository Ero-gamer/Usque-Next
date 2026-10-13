package io.github.georgexie2333.usque

import io.flutter.plugin.common.MethodChannel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OnboardingPermissionCoordinatorTest {
    @Test
    fun onboardingStatusAndPreparationNeverInspectOrRequestVpn() {
        val host = Host().apply { failVpnInspection = true }
        val coordinator = OnboardingPermissionCoordinator(host)
        val result = Result()
        assertEquals(mapOf("notification" to "notRequested"), coordinator.status())
        coordinator.prepare(result)
        assertEquals(listOf("notification"), host.launches)
        coordinator.finishNotification()
        assertEquals(1, result.completions)
        assertEquals(mapOf("notification" to "notGranted"), result.value)
        assertEquals(0, host.connections)
        assertEquals(0, host.inspections)
    }

    @Test
    fun deniedOrUnverifiedVpnNeverRequestsNotifications() {
        for (reportedGrant in listOf(false, true)) {
            val host = Host()
            val coordinator = OnboardingPermissionCoordinator(host)
            val result = Result()
            coordinator.connect(result, true) { host.connections++ }
            coordinator.finishConfirmation(true)
            coordinator.finishVpn(reportedGrant)
            assertEquals("VPN_PERMISSION_DENIED", result.code)
            assertEquals(listOf("confirmation", "vpn"), host.launches)
            assertEquals(1, result.completions)
            assertEquals(0, host.connections)
        }
    }

    @Test
    fun previouslyPreparedVpnIsNotInspectedBeforeConfirmation() {
        val host =
            Host().apply {
                vpn = true
                requested = true
            }
        val coordinator = OnboardingPermissionCoordinator(host)
        coordinator.prepare(Result())
        coordinator.connect(Result(), true) { host.connections++ }
        assertEquals(listOf("confirmation"), host.launches)
        assertEquals(0, host.inspections)
        coordinator.finishConfirmation(true)
        assertEquals(1, host.connections)
        host.vpn = false
        coordinator.connect(Result(), true) { host.connections++ }
        coordinator.finishConfirmation(true)
        assertEquals(listOf("confirmation", "confirmation", "vpn"), host.launches)
        assertEquals(1, host.connections)
    }

    @Test
    fun cancellationKeepsOldDialogReservedUntilItsCallback() {
        val host = Host()
        val coordinator = OnboardingPermissionCoordinator(host)
        val first = Result()
        coordinator.connect(first, true) { host.connections++ }
        coordinator.finishConfirmation(true)
        coordinator.cancelConnection("VPN_PERMISSION_CANCELLED", "cancelled")
        val second = Result()
        coordinator.prepare(second)
        assertEquals("VPN_PERMISSION_IN_PROGRESS", second.code)
        host.vpn = true
        coordinator.finishVpn(true)
        assertEquals(1, first.completions)
        assertEquals(0, host.connections)
        val third = Result()
        host.requested = true
        coordinator.prepare(third)
        coordinator.finishVpn(true)
        assertEquals(1, third.completions)
    }

    @Test
    fun notificationLaunchFailureAndDenialDoNotGateSetup() {
        val host =
            Host().apply {
                vpn = true
                failNotification = true
            }
        val coordinator = OnboardingPermissionCoordinator(host)
        val failed = Result()
        coordinator.prepare(failed)
        assertEquals(1, failed.completions)
        assertFalse(host.requested)
        host.failNotification = false
        val denied = Result()
        coordinator.prepare(denied)
        coordinator.finishNotification()
        assertEquals(1, denied.completions)
        assertEquals(mapOf("notification" to "notGranted"), denied.value)
        assertEquals(0, host.inspections)
    }

    @Test
    fun grantedVpnConnectsImmediatelyWithoutRequestingNotifications() {
        val host = Host()
        val coordinator = OnboardingPermissionCoordinator(host)
        coordinator.connect(Result(), true) { host.connections++ }
        coordinator.finishConfirmation(true)
        host.vpn = true
        coordinator.finishVpn(true)
        assertEquals(listOf("confirmation", "vpn"), host.launches)
        assertEquals(1, host.connections)
        assertFalse(host.requested)
    }

    @Test
    fun cancellingConfirmationDoesNotPrepareVpnAndCanBeRetried() {
        val host = Host().apply { failVpnInspection = true }
        val coordinator = OnboardingPermissionCoordinator(host)
        val first = Result()
        coordinator.connect(first, true) { host.connections++ }
        coordinator.finishConfirmation(false)
        coordinator.finishConfirmation(true)
        assertEquals("VPN_PERMISSION_CANCELLED", first.code)
        assertEquals(1, first.completions)
        assertEquals(0, host.inspections)
        assertEquals(0, host.connections)
        coordinator.connect(Result(), true) { host.connections++ }
        assertEquals(listOf("confirmation", "confirmation"), host.launches)
    }

    @Test
    fun cancelledPendingConfirmationCannotStartAConnection() {
        val host = Host().apply { failVpnInspection = true }
        val coordinator = OnboardingPermissionCoordinator(host)
        val result = Result()
        coordinator.connect(result, true) { host.connections++ }
        coordinator.cancelConnection("VPN_PERMISSION_CANCELLED", "cancelled")
        coordinator.finishConfirmation(true)
        assertEquals(1, result.completions)
        assertEquals(0, host.inspections)
        assertEquals(0, host.connections)
        coordinator.connect(Result(), true) { host.connections++ }
        assertEquals(listOf("confirmation", "confirmation"), host.launches)
    }

    @Test
    fun confirmationDoesNotLeaveAStaleDialogAfterRecreation() {
        val host = Host()
        val original = OnboardingPermissionCoordinator(host)
        original.connect(Result(), true) { host.connections++ }
        assertNull(original.outstandingDialog())
        original.destroy()
        original.finishConfirmation(true)
        assertEquals(0, host.inspections)
        val restored = OnboardingPermissionCoordinator(host)
        restored.restoreOutstandingDialog(original.outstandingDialog())
        restored.connect(Result(), true) { host.connections++ }
        assertEquals(listOf("confirmation", "confirmation"), host.launches)
    }

    @Test
    fun destroyCompletesOnceAndLateCallbacksCannotConnect() {
        val host = Host()
        val coordinator = OnboardingPermissionCoordinator(host)
        val result = Result()
        coordinator.connect(result, true) { host.connections++ }
        coordinator.finishConfirmation(true)
        coordinator.destroy()
        host.vpn = true
        coordinator.finishVpn(true)
        coordinator.destroy()
        assertEquals(1, result.completions)
        assertEquals(0, host.connections)
    }

    @Test
    fun recreatedActivityDrainsItsOldDialogBeforeAcceptingAnotherRequest() {
        val host = Host()
        val original = OnboardingPermissionCoordinator(host)
        original.prepare(Result())
        val saved = original.outstandingDialog()
        original.destroy()
        val restored = OnboardingPermissionCoordinator(host)
        restored.restoreOutstandingDialog(saved)
        val busy = Result()
        restored.prepare(busy)
        assertEquals("VPN_PERMISSION_IN_PROGRESS", busy.code)
        restored.finishNotification()
        restored.prepare(Result())
        assertEquals(listOf("notification"), host.launches)
    }

    @Test
    fun proxyOnlyConnectionDoesNotInspectOrRequestVpn() {
        val host =
            Host().apply {
                failVpnInspection = true
                requested = true
            }
        OnboardingPermissionCoordinator(host).connect(Result(), false) { host.connections++ }
        assertEquals(1, host.connections)
        assertTrue(host.launches.isEmpty())
    }

    private class Host : OnboardingPermissionCoordinator.Host {
        var failVpnInspection = false
        var vpn = false
        var requested = false
        var failNotification = false
        var connections = 0
        var inspections = 0
        val launches = mutableListOf<String>()

        override fun vpnGranted(): Boolean {
            inspections++
            if (failVpnInspection) error("VPN inspection unavailable")
            return vpn
        }

        override fun notificationState(): String = if (requested) "notGranted" else "notRequested"

        override fun launchVpnConfirmation() {
            launches.add("confirmation")
        }

        override fun launchVpn() {
            launches.add("vpn")
        }

        override fun launchNotification() {
            if (failNotification) error("unavailable")
            requested = true
            launches.add("notification")
        }
    }

    private class Result : MethodChannel.Result {
        var completions = 0
        var value: Any? = null
        var code: String? = null

        override fun success(result: Any?) {
            completions++
            value = result
        }

        override fun error(
            errorCode: String,
            errorMessage: String?,
            errorDetails: Any?,
        ) {
            completions++
            code =
                errorCode
        }

        override fun notImplemented() {
            completions++
        }
    }
}
