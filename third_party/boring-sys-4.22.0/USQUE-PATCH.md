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
the Rust client to keep the Chrome 131 TLS 1.3 cipher order and ECH GREASE AEAD
stable on devices without AES acceleration. Bindgen generates its declaration
through the existing headers; no C++ symbol names or private structure layouts
are duplicated in Rust.

Only the Chrome profile calls it, before creating SSL connections. The Default
profile retains BoringSSL's hardware-dependent preferences. This changes no
global CPU flags, encryption implementation dispatch, certificate verification
or client authentication. Actual AES operations still use hardware acceleration
only when the CPU provides it. The adapter is tied to this pinned BoringSSL
revision and must be reviewed if that revision changes.
