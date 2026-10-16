package io.github.georgexie2333.usque

import org.json.JSONObject

/** Only advertise ClientHello presets supported by the linked native engine. */
internal object TlsFingerprintSettings {
    fun capabilities(value: String?): List<String> {
        if (value == null || value.length > 4096) return emptyList()
        val source = runCatching { JSONObject(value).optJSONArray("tls_fingerprints") }.getOrNull()
        return (0 until minOf(source?.length() ?: 0, 32))
            .mapNotNull { source?.opt(it) as? String }
            .filter { it == "default" || it == "chrome155" }
            .distinct()
    }
}
