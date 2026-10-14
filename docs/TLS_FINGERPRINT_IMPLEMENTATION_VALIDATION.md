# TLS fingerprint implementation validation

Date: 2026-10-14. Scope: the production implementation of
[issue #110](https://github.com/GeorgeXie2333/usque-app/issues/110) on local `dev`.
The [user guide](TLS_FINGERPRINT.md) describes the controls and their limits.

The initial implementation results below precede the review fixes. The
[post-review section](#post-review-fixes-2026-10-14) records that later candidate
separately; earlier counts, binary hashes and live results retain their original
scope.

## Source identity and evidence limits

The working tree starts from `6532958a642fe9e9729f22dab3330ce1ca09f0cd` and
contains uncommitted implementation and test changes. This is a working-tree
candidate, not a separately committed or packaged source snapshot. The baseline
commit alone does not identify all tested source; this document is not a complete
reproducible source archive.

The earlier [Chrome ClientHello experiment](CHROME_FINGERPRINT_VALIDATION.md)
keeps its original candidate, test counts and live WARP results. Those results
are not reassigned to this production implementation. The new live run below
uses the production helper and the current candidate's test executable. A
current implementation test is only passed when its command has completed
successfully.

## Implemented behavior

- **Settings → Advanced network settings → Transport → TLS fingerprint** offers
  **Default** and **Chrome 131**. The setting is shared across accounts and uses
  the existing save/apply flow; an active stable connection uses a controlled
  reconnect when the selection changes.
- Schema 25 migrates existing configurations to Default. Profile protobuf field
  26 and capability field 48 carry the choice and supported profiles. Unknown
  explicit values are rejected. An older engine cannot silently downgrade a
  saved Chrome selection.
- The same profile reaches H2, H3, Auto fallback, H3 L4 and refreshed identities.
  Default preserves existing handshake preferences. Chrome 131 is a fixed TLS
  ClientHello profile with the required QUIC adaptation, not complete browser
  traffic impersonation. ECH GREASE is not real ECH encryption.
- Client-certificate authentication and endpoint SPKI verification remain in
  their existing owner. BoringSSL's post-quantum feature and Brotli certificate
  decoding are production dependencies for the Chrome profile.

## Security and validation scope

The change adds no credentials to saved profile fields, diagnostic output or
logs. The selection is non-secret. Credentials and pins retain their existing
storage and verification paths. The fingerprint helper changes TLS preferences
and an informational handshake callback; it does not replace peer verification.

Certificate decompression rejects nonstandard large windows, malformed or
truncated streams, trailing input and inputs or outputs above 1 MiB. Actual
byte-buffer allocations share a 4 MiB + 64 KiB limit; Huffman and integer tables
retain the decoder's format-bounded allocations. This is not a claim that the
whole TLS connection or application consumes only that amount of memory.

The test suite includes in-memory H2 TLS and H3 QUIC peers that require the
expected client identity, accept the correct endpoint key and reject a wrong
SPKI. Decoder fixtures cover the allocation and byte limits, failed writes and
invalid streams. Two property tests each exercise 256 cases of arbitrary bytes
and mutated/truncated fixtures, following the repository's existing parser-fuzz
style. ClientHello tests inspect actual outgoing handshakes. GUI tests use a fake
engine; they do not prove native connection behavior.

These workstation checks create no TUN/Wintun session and do not apply WFP,
routes, interface DNS or system-proxy changes. No MSI installation, release APK
installation, upgrade or publication is part of this validation. Native VPN
reconnect cleanup, platform restoration and independent leak observation require
the isolated environments in [Contributing](../CONTRIBUTING.md).

## Commands and outcomes

Commands are shown from the repository root unless a directory is specified.
Native Rust commands use the checked-in helper; Flutter and Dart use the pinned
SDK resolved from local configuration.

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test` | Passed: 1,754 tests; nine explicitly ignored |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2` | Passed; Windows x64-v2 release compile only |
| `& ./tool/build_android_rust.ps1 -AbiFilter arm64-v8a -CargoAction clippy` | Passed |
| `& ./tool/build_android_rust.ps1 -Profile debug -AbiFilter all` | Passed: arm64-v8a, armeabi-v7a and x86_64; compile only |
| `buf lint` | Passed |
| `buf format --exit-code --diff` | Passed |
| `pwsh -NoProfile -File tool/check_source.ps1` | Passed after initializing the supported native environment; first sandboxed attempt stalled in Dart |
| `python tool/check_repository_policy.py` | Passed using the verified Python 3.12 executable |
| `git diff --check` | Passed |

From `apps/usque_gui`:

| Command | Result |
| --- | --- |
| `flutter pub get --enforce-lockfile` | Passed |
| `dart format --output=none --set-exit-if-changed lib test` | Passed |
| `flutter analyze --no-pub` | Passed |
| `flutter test --no-pub` | Passed: 1,097 tests, including the Windows golden suite |
| `& ../../tool/prepare_windows_plugin_junctions.ps1 -FlutterProject .` | Passed |
| `flutter build windows --release --no-pub --split-debug-info=build/symbols/windows` | Passed; compile only |
| `flutter build apk --debug --config-only --no-pub` | Passed; configuration only |

From `apps/usque_gui/android`:

| Command | Result |
| --- | --- |
| `.\gradlew.bat --no-daemon :app:ktlintCheck` | Passed |
| `.\gradlew.bat --no-daemon :app:testDebugUnitTest :app:lintDebug` | Passed: 462 unit tests, zero failures/errors; lint passed after the native-build retry |

Environment retries included a native `libclang.dll` load failure in a Windows
helper run outside the filesystem sandbox and a stalled Dart step in the first
aggregate run. Native compilation was retried in the default sandbox. The
aggregate's exact command then passed with approved access after initializing
the supported native environment. These initial failures are not Cloudflare
rejections, and cached native artifacts do not establish a fresh unsandboxed
native build.

All final native helper and Gradle commands above completed successfully after
those retries. The isolated checks below remain separate from these workstation
results.

## Production-helper live compatibility run

At 2026-10-14 10:44 Asia/Singapore (02:44 UTC), the exact opt-in probe passed
against the public Consumer ingress `162.159.199.2:443`. It read the existing
active Consumer identity from the credential vault without enrolling, refreshing,
persisting or revoking an identity. Every attempt used a fresh TLS context and
connection, the selected production fingerprint helper, client-certificate
authentication and the registered endpoint SPKI pin.

| Carrier | Default controls | Chrome 131 trials | Acceptance |
| --- | --- | --- | --- |
| H2 / TCP | 3/3 | 3/3 | Authenticated TLS 1.3 and CONNECT-IP HTTP 200 on all six |
| H3 / QUIC | 3/3 | 3/3 | Authenticated TLS 1.3 and CONNECT-IP HTTP 200 on all six |

The Chrome attempts also passed the outgoing ClientHello checks. H2 received
no ALPN selection and used the existing HTTP/2 prior-knowledge behavior; H3
negotiated `h3` and did not fall back to H2. The test carried no user application
traffic and did not measure throughput. Its results apply to this account,
endpoint, network and date; they do not establish every account type or endpoint,
real ECH, complete Chrome traffic impersonation or native VPN cleanup.

The test executable was `target/debug/deps/usque_transport-bcbfd1bead1fc724.exe`,
SHA-256 `15a99be68f9e94b285f8aa2d4a5f7f439ff7ad08f1dd9ca70e991dfe6ccc9f64`.
This identifies the executed binary, not a complete source archive.

Reproduction requires an explicitly authorized local identity and ingress. Use
the native build helper above first, replace the local config placeholder, and
run only this named ignored test. Do not run the whole ignored suite.

```powershell
$env:USQUE_LIVE_CHROME_PROBE = '1'
$env:USQUE_LIVE_CONFIG = '<authorized local Usque config.json path>'
$env:USQUE_LIVE_ENDPOINT = '162.159.199.2:443'
& .\target\debug\deps\usque_transport-bcbfd1bead1fc724.exe 'chrome_fingerprint_tests::live::cloudflare_accepts_chrome_h2_and_h3_without_tun' --exact --ignored --nocapture --test-threads=1
```

The executable suffix changes with the build; use the `usque_transport-*.exe`
reported by the helper for a new candidate. This command passed separately as
one test with 12 authenticated CONNECT-IP successes. An unreachable default
control cannot establish a Chrome-profile rejection.

| Environment-dependent check | Result |
| --- | --- |
| Exact live WARP probe of this production candidate | Passed: 12/12 authenticated CONNECT-IP connections as recorded above |
| Windows snapshot VM and native VPN lifecycle | `not_run`; isolated environment unavailable |
| Dedicated Android device/emulator lifecycle | `not_run`; isolated environment unavailable |
| External network observer and leak checks | `not_run`; isolated environment unavailable |
| Controlled performance lab | `not_run`; isolated environment unavailable |

## Post-review fixes: 2026-10-14

This candidate adds review fixes to the same local `dev` working tree based on
`6532958a642fe9e9729f22dab3330ce1ca09f0cd`. Validation preceded the local commit;
the commit containing this appendix records the reviewed implementation and
tests. The initial implementation's source limitation and binary hash above
remain unchanged and must not be used to identify this later source or executable.

### Corrections and regression coverage

On devices without AES acceleration, BoringSSL previously reordered the TLS 1.3
suites even when Chrome 131 was selected: `set_cipher_list` only governs earlier
TLS versions. The pinned native C ABI adapter now sets the existing per-context
AES preference for Chrome, preserving its fixed TLS 1.3 order and ECH GREASE AEAD
selection. Default keeps the native hardware-dependent preferences. This does
not change global CPU flags or cryptographic instruction dispatch. The
[vendor patch notes](../third_party/boring-sys-4.22.0/USQUE-PATCH.md) describe the
adapter and revision boundary. The native build script also watches its local
source and patch inputs so a cached library or generated binding cannot hide
this API change.

Two added Rust test entries exercise an isolated x86/x86_64 child process. Its
`OPENSSL_ia32cap=~0x200000000000000` mask disables AES-NI before BoringSSL starts,
and the child checks that `EVP_has_aes_hardware()` reports zero. Actual H2 and H3
ClientHellos must still match the strict Chrome profile; Default must retain
ChaCha-first ordering without Chrome-only extensions. A completion marker
prevents a zero-matching-test false pass, and a deadline with process cleanup
bounds the test. The test does not mutate the parent process environment and
does not claim runtime coverage on a non-x86 architecture.

Startup now treats a saved non-default TLS fingerprint as requiring capability
discovery, including Custom endpoints and Zero Trust. Temporary discovery
failures no longer consume the one automatic-connection attempt. Four new
Flutter regressions cover recovery and user cancellation for both account/endpoint
cases. These use a fake engine and establish controller behavior only.

### Post-review commands and outcomes

The same command locations and pinned-toolchain requirements as above apply.

| Command from repository root | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed through the final aggregate command |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test` | Passed: 1,756 tests; nine explicitly ignored |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2` | Passed; Windows x64-v2 release compile only |
| `& ./tool/build_android_rust.ps1 -AbiFilter arm64-v8a -CargoAction clippy` | Passed |
| `& ./tool/build_android_rust.ps1 -Profile debug -AbiFilter all` | Passed: arm64-v8a, armeabi-v7a and x86_64; compile only |
| `pwsh -NoProfile -File tool/check_source.ps1` | Passed |
| `python tool/check_repository_policy.py` | Passed using the verified Python 3.12 executable |
| `git diff --check` | Passed |

From `apps/usque_gui`:

| Command | Result |
| --- | --- |
| `flutter pub get --enforce-lockfile` | Passed |
| `dart format --output=none --set-exit-if-changed lib test` | Passed |
| `flutter analyze --no-pub` | Passed |
| `flutter test --no-pub` | Passed: 1,101 tests, including four new startup regressions |
| `& ../../tool/prepare_windows_plugin_junctions.ps1 -FlutterProject .` | Passed |
| `flutter build windows --release --no-pub --split-debug-info=build/symbols/windows` | Passed; compile only |
| `flutter build apk --debug --config-only --no-pub` | Passed; configuration only |

From `apps/usque_gui/android`:

| Command | Result |
| --- | --- |
| `.\gradlew.bat --no-daemon :app:ktlintCheck` | Passed through the final aggregate command |
| `.\gradlew.bat --no-daemon :app:testDebugUnitTest :app:lintDebug` | Passed; unchanged Kotlin tests/lint were up-to-date, retaining 462 tests with zero failures/errors; all three rebuilt JNI libraries rechecked |

### Post-review live and no-AES results

The later test executable is again
`target/debug/deps/usque_transport-bcbfd1bead1fc724.exe`, now SHA-256
`d9fdd889a385e71853797b5f08aef8c550610ab216aa3a49fc7b25f0d3d04305`.
The unchanged filename does not imply unchanged contents; the earlier binary
hash and its original 12/12 result remain recorded above.

Two fresh live matrices passed against `162.159.199.2:443` with the same
read-only Consumer identity and endpoint pin. The normal run was recorded at
2026-10-14 14:04:38 Asia/Singapore (06:04:38 UTC); the AES-NI-masked process
was recorded at 14:04:40 (06:04:40 UTC).

| Process | H2 Default | H2 Chrome 131 | H3 Default | H3 Chrome 131 |
| --- | --- | --- | --- | --- |
| Normal CPU capabilities | 3/3 | 3/3 | 3/3 | 3/3 |
| AES-NI masked for that process | 3/3 | 3/3 | 3/3 | 3/3 |

All 24 attempts completed authenticated TLS 1.3 and CONNECT-IP HTTP 200. H2
again received no ALPN selection; H3 negotiated `h3`. Default advertised the
TLS 1.3 prefix `[4865, 4866, 4867]` normally and `[4867, 4865, 4866]` with AES-NI
masked, while Chrome retained `[4865, 4866, 4867]` in both processes. The strict
Chrome ClientHello checks passed for both carriers. A separate masked run also
passed all 18 authentication and decoder tests, including in-memory H2/H3
client authentication and rejection of the wrong endpoint pin.

To reproduce the process isolation, use the verified test executable and
authorized config from the earlier reproduction instructions. The following
PowerShell creates each child with its own environment; it does not set CPU or
credential variables in the parent process or change system settings. The mask
applies to x86/x86_64 and disables AES-NI only, not the machine's actual hardware.

```powershell
$probeExecutable = (Resolve-Path '.\target\debug\deps\usque_transport-bcbfd1bead1fc724.exe').Path
$probeConfig = '<authorized local Usque config.json path>'
foreach ($maskAes in @($false, $true)) {
    $start = [System.Diagnostics.ProcessStartInfo]::new($probeExecutable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.ArgumentList.Add('chrome_fingerprint_tests::live::cloudflare_accepts_chrome_h2_and_h3_without_tun')
    $start.ArgumentList.Add('--exact')
    $start.ArgumentList.Add('--ignored')
    $start.ArgumentList.Add('--nocapture')
    $start.ArgumentList.Add('--test-threads=1')
    $start.Environment['USQUE_LIVE_CHROME_PROBE'] = '1'
    $start.Environment['USQUE_LIVE_CONFIG'] = $probeConfig
    $start.Environment['USQUE_LIVE_ENDPOINT'] = '162.159.199.2:443'
    $start.Environment.Remove('OPENSSL_ia32cap') | Out-Null
    if ($maskAes) {
        $start.Environment['OPENSSL_ia32cap'] = '~0x200000000000000'
    }
    $probeProcess = [System.Diagnostics.Process]::Start($start)
    try {
        if (-not $probeProcess.WaitForExit(420000)) {
            $probeProcess.Kill($true)
            $probeProcess.WaitForExit()
            throw 'The bounded live probe timed out.'
        }
        if ($probeProcess.ExitCode -ne 0) {
            throw "The live probe failed with exit code $($probeProcess.ExitCode)."
        }
    } finally {
        $probeProcess.Dispose()
    }
}
```

For the separate non-networked authentication/decoder run, use a child with the
same `OPENSSL_ia32cap` mask and arguments
`tls_fingerprint::tests:: --nocapture`, without `--ignored` or
the live-probe variables. The workspace suite also runs the bounded isolated
ClientHello regression, whose child explicitly verifies that BoringSSL reports
no AES hardware.

These results establish this candidate's acceptance at the tested Consumer
endpoint on this network and date, not all accounts or endpoints, full browser
impersonation or native VPN behavior. Snapshot VM, dedicated Android device,
external leak observation and performance lab checks remain **not_run**. No
installation, privileged network mutation or publication was performed.

---

WARP is a trademark and/or registered trademark of Cloudflare, Inc. in the United States and other jurisdictions.
