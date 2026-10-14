package io.github.georgexie2333.usque

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class TlsFingerprintSettingsTest {
    @Test
    fun onlyExplicitKnownCapabilitiesEnablePresets() {
        for (value in listOf(null, "{}", "invalid", "x".repeat(4097))) {
            assertEquals(emptyList<String>(), TlsFingerprintSettings.capabilities(value))
        }
        assertEquals(
            listOf("default", "chrome131"),
            TlsFingerprintSettings.capabilities(
                """{"tls_fingerprints":["default","chrome131","unknown",2,"Chrome131","chrome131"]}""",
            ),
        )
    }

    @Test
    fun connectionUsesTheSavedFingerprint() {
        val requested = """{"id":"a","tls_fingerprint":"default"}"""
        val saved = """{"profiles":[{"id":"a","tls_fingerprint":"chrome131"}]}"""
        assertEquals(
            "chrome131",
            JSONObject(NetworkSettingsFields.savedProfile(requested, saved)).getString("tls_fingerprint"),
        )
    }
}
