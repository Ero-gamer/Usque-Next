# Chrome ClientHello compatibility experiment

Date: 2026-10-14. Scope: [issue #110](https://github.com/GeorgeXie2333/usque-app/issues/110),
authenticated Cloudflare WARP MASQUE CONNECT-IP over H2 and H3.

## Candidate and fingerprint

The experiment starts from `6532958a642fe9e9729f22dab3330ce1ca09f0cd` with
the test changes in this working tree. The test-only implementation is in
[`chrome_fingerprint_tests.rs`](../crates/usque-transport/src/chrome_fingerprint_tests.rs).
Every injection point and probe field is under `cfg(test)`. Normal applications
do not expose or activate this profile.

The reference is the fixed
[uTLS `HelloChrome_131` definition](https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_parrots.go).
BoringSSL constructs the actual handshake. The profile sets the TLS cipher
order, signature algorithms, GREASE, shuffled extensions, X25519MLKEM768 and
X25519 key shares, P-256/P-384 fallback groups, OCSP/SCT requests, Brotli
certificate decompression and ECH GREASE. H2 offers `h2,http/1.1`, TLS 1.3/1.2,
and the Chrome 131 ALPS codepoint. H3 offers `h3` and TLS 1.3 with QUIC transport
parameters and no TLS compatibility session ID.

The existing BoringSSL version requires its `pq-experimental` feature for ML-KEM.
That feature and the bounded Brotli decoder are development dependencies only.
The release dependency graph must be checked separately from the test graph.

This tests Chrome 131 TLS preferences, with the required QUIC adaptation for H3.
It does not claim byte-for-byte equivalence to a current Chrome installation,
Chrome QUIC packetization/transport parameters, HTTP SETTINGS, resumption,
real ECH, or resistance to traffic classification. ECH GREASE is not ECH
encryption. Cloudflare acceptance is a narrower question than indistinguishability.

## Safety and success criteria

The ignored Windows test requires an explicit config path, IPv4 WARP ingress
endpoint on port 443 and opt-in variable. It reads only the active account's
private key, endpoint pin and assigned addresses from Windows Credential
Manager. It does not enroll, refresh, persist or revoke an identity. The
production client-certificate and endpoint-public-key verification remain active.

Connections use ordinary TCP/UDP sockets, no Agent, TUN, routes, interface DNS,
WFP, system proxy or Kill Switch. No user traffic is routed through the test.
Each successful tunnel is shut down and its driver joined. Attempts have a
30-second outer deadline and cancellation; transport-owned drop guards clean up
failed startups. No unrelated ignored tests are run.

The message callback retains only public algorithm/extension identifiers and
protocol metadata. Randoms, key shares, SNI, credentials, certificates, traffic
payloads and TLS key logs are not recorded. Generated logs and source/binary
hashes remain under ignored `target/issue110-chrome`.

For each carrier the test alternates three default controls with three fresh
Chrome-profile connections. A pass requires the observed ClientHello to match
the tested profile, authenticated TLS completion, and an HTTP 200 response to
the existing Cloudflare CONNECT-IP request. H3 never falls back to H2. TLS
completion alone is not a pass. This test does not measure tunneled throughput
or establish VPN lifecycle, leak prevention, Android device or Zero Trust coverage.

## Reproduction

Follow the native-environment requirements in [Contributing](../CONTRIBUTING.md).
The deterministic suite checks actual outbound H2/H3 ClientHello messages
without an external network, including comparison with the H2 wire record and
rejection of truncated messages.

```powershell
cargo fmt --all --check
& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy
& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test
& .\tool\build_windows_rust_release.ps1 -Variant x64-v2
```

After the helper compiles the tests, identify the `usque_transport-*.exe` named
in its output. Run only that executable with the exact ignored test name:

```powershell
$env:USQUE_LIVE_CHROME_PROBE = '1'
$env:USQUE_LIVE_CONFIG = Join-Path $env:LOCALAPPDATA 'Usque\config.json'
$env:USQUE_LIVE_ENDPOINT = '162.159.199.2:443'
& '<compiled transport test executable>' 'chrome_fingerprint_tests::live::cloudflare_accepts_chrome_h2_and_h3_without_tun' --exact --ignored --nocapture --test-threads=1
```

The endpoint is a public shared Consumer ingress representative. Use only an
explicit authorized endpoint; the harness performs no discovery or scanning.
An unreachable control cannot establish whether the Chrome profile is accepted.

## Results

The final live matrix passed against `162.159.199.2:443` using the existing
active account and its configured SNI. Each attempt used a fresh TLS context
and connection. Results apply to this account, endpoint, network and date.

| Carrier | Default controls | Chrome 131 TLS trials | CONNECT-IP response |
| --- | --- | --- | --- |
| H2 / TCP | 3/3 accepted | 3/3 accepted | HTTP 200 on all six |
| H3 / QUIC | 3/3 accepted | 3/3 accepted | HTTP 200 on all six |

All 12 attempts completed authenticated TLS 1.3. The Chrome attempts also
passed the outgoing cipher, extension-set, group, signature, key-share-group,
version, ALPN, compression and GREASE checks. H2 received no ALPN selection,
then successfully used the existing HTTP/2 prior-knowledge behavior. H3
negotiated `h3` and remained on QUIC throughout.

This establishes that the tested Cloudflare WARP endpoint accepts both of
these ClientHello profiles. It does not establish compatibility with every
Chrome version, account type, endpoint, network or optional TLS extension.

The final test binary was `usque_transport-973c734d8695012e.exe`, SHA-256
`885203b2dd1d82fb15091384405f8e7bc81c51bb6974d7c0c76603f85cc552fe`.
The local eight-file source manifest `target/issue110-chrome/source-hashes.json`
has SHA-256
`09bd652c4558958046735d138108025f8ec9fe5c88bdd559e5a087ea14372dc9`.
It covers the lockfile, transport manifest, H2/H3/module injection points and
the three probe source files. This records a working-tree candidate, not a
separate committed source snapshot. The manifest and sanitized `results.json`
remain local; this document alone is not a complete reproducible source archive.

The following checks completed for the tested source:

| Command / check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test` | Passed: 1,727 tests; nine explicitly ignored |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2` | Passed: Windows x64-v2 release compile only |
| Exact ignored live-test command above | Passed separately: one test, 12 authenticated CONNECT-IP successes |
| `cargo tree --locked -p usque-transport --edges normal,build,features --prefix none` | No probe ML-KEM feature or Brotli decoder in the production dependency graph |
| Android device, OS VPN lifecycle and external leak validation | `not_run`; outside this socket-only compatibility experiment |

Initial native attempts exposed two environment limitations: the sandbox
prevented an existing L4 test from opening the Windows root certificate store,
while an unsandboxed native build reported a load failure for the NDK
`libclang.dll`. Compilation succeeded in the sandbox; the exact workspace
test helper then passed with those native artifacts and read access to the
root store. No certificate-store contents or build safety checks were changed.
This is not evidence of a fresh unsandboxed native build. The initial local
failures are not Cloudflare rejections.
