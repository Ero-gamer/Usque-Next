# Usque patch notes

This directory contains the crates.io `boring-sys` 4.22.0 source published
from upstream commit `467cb51c987fbb0041b2f31bd56b697a956e5cea`.

## Build portability

Usque changes the Android cross-compilation setup in `build/main.rs`.
Upstream passes the API-unqualified Rust target (for example
`aarch64-linux-android`) through `CMAKE_C_COMPILER_TARGET`. That value
overrides the Android NDK toolchain's API-qualified target and prevents Clang
from locating Android CRT objects on Windows hosts.

The patch lets the NDK CMake toolchain own Android cross-compilation and
defines the three CMake language flag variables so `cmake-rs` cannot copy the
same API-unqualified target back from `cc-rs`. It also keeps target-specific
`CC` and `CXX` variables (needed by non-CMake dependencies such as `ring`)
from replacing the compiler selected by the Android CMake toolchain.
The build script explicitly tracks its build, patch and native-source directories
so local C API edits invalidate both the native library and generated bindings.

## Fixed TLS fingerprint preference

`ssl.h` and `ssl_lib.cc` expose the small C ABI adapter
`USQUE_SSL_CTX_set_aes_cipher_preference`. It calls the existing C++ per-context
`SSL_CTX_set_aes_hw_override_for_testing(ctx, true)` preference setter, allowing
the Rust client to keep the Chrome TLS 1.3 cipher order and ECH GREASE AEAD
stable on devices without AES acceleration. Bindgen generates its declaration
through the existing headers; no C++ symbol names or private structure layouts
are duplicated in Rust.

Only the Chrome profile calls it, before creating SSL connections. The Default
profile retains BoringSSL's hardware-dependent preferences. This changes no
global CPU flags, encryption implementation dispatch, certificate verification
or client authentication. Actual AES operations still use hardware acceleration
only when the CPU provides it. The adapter is tied to this pinned BoringSSL
revision and must be reviewed if that revision changes.

## Chrome 155 extensions and interoperability probe

`USQUE_SSL_CTX_set_chrome155_extensions` opts one context into the ClientHello
additions from uTLS commit `ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67`:
ALPS codepoint 17613, signature GREASE from independent seed slot 7 followed by
ML-DSA-44/65/87, and the 28 ordered public trust-anchor IDs from Chrome
155.0.8059.40. The reference is
[u_parrots.go](https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_parrots.go)
and [u_chrome155.go](https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_chrome155.go).
The flag defaults to false and must be configured before creating connections.

Both ALPS codepoints have separate extension-table entries, so an unsolicited
old/new response is rejected by the existing sent-extension checks. New ALPS
also uses 17613 in the client EncryptedExtensions and server parsing. All
additions participate in BoringSSL's ordinary handshake transcript.

This is an advertisement experiment, not an implementation of ML-DSA. The
existing signature verification preference validation, peer algorithm check,
EVP verification, client authentication and endpoint SPKI checks are retained.
An unsupported peer algorithm must fail; the advertised root-store IDs do not
install roots or grant certificate trust. After the 27-attempt Consumer WARP
experiment selected ECDSA throughout, the production Chrome 155 profile enables
this flag. A test-only Chrome 131 control disables it. Default retains its native
wire preferences. The experiment does not establish ML-DSA cryptographic support
or compatibility with every WARP account/ingress; see the
[validation record](../../docs/CHROME155_WARP_VALIDATION.md).
