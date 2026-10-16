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
            listOf("default", "chrome155"),
            TlsFingerprintSettings.capabilities(
                """{"tls_fingerprints":["default","chrome155","unknown",2,"Chrome155","chrome155"]}""",
            ),
        )
    }

    @Test
    fun connectionUsesTheSavedFingerprint() {
        val requested = """{"id":"a","tls_fingerprint":"default"}"""
        val saved = """{"profiles":[{"id":"a","tls_fingerprint":"chrome155"}]}"""
        assertEquals(
            "chrome155",
            JSONObject(NetworkSettingsFields.savedProfile(requested, saved)).getString("tls_fingerprint"),
        )
    }
}
