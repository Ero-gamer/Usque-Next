# Chrome 155 WARP signature negotiation

## Result and decision

On 2026-10-17 at 05:03 Asia/Taipei (2026-10-16 21:03 UTC), the selected
Consumer identity completed all **27/27** trials at `162.159.199.2:443`.

| Path | Default | Chrome 131 control | Chrome 155 candidate |
| --- | --- | --- | --- |
| H2 CONNECT-IP | 3/3 | 3/3 | 3/3 |
| H3 CONNECT-IP | 3/3 | 3/3 | 3/3 |
| L4 CONNECT plus verified HTTPS | 3/3 | 3/3 | 3/3 |

Every trial reported an EC server public key, an ECDSA/SHA-384 certificate
issuer signature, and **ECDSA P-256/SHA-256 (`0x0403`) CertificateVerify**.
The certificate issuer signature is distinct from the handshake signature.
All endpoint SPKI pins and TLS Finished messages verified. H2/H3 completed
authenticated CONNECT-IP. L4 delivered a final 2xx CONNECT stream, verified
the inner HTTPS certificate for `one.one.one.one`, and received HTTP 200.

Chrome 155 offered ML-DSA-44/65/87 (`0x0904`/`0x0905`/`0x0906`), but none was
selected. Thus this tested Consumer ingress did not require ML-DSA verification.
The application replaces the unreleased Chrome 131 option with Chrome 155;
Default retains its native preferences. Full ML-DSA verification remains
unimplemented: peers requiring it fail closed. No certificate or signature
verification was disabled to obtain these results.

## Template and test design

The reference is uTLS commit `ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67`,
[HelloChrome_155](https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_parrots.go),
with the ordered 28 public IDs in
[u_chrome155.go](https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_chrome155.go).
The fixed Chrome 155.0.8059.40 sample is not a promise to follow future browser
or Root Store component updates. The motivating
[Xray issue](https://github.com/XTLS/Xray-core/issues/7131) is context, not
evidence of WARP compatibility or this application's resistance to filtering.

BoringSSL writes the new ALPS codepoint 17613, signature GREASE from seed slot
7, ML-DSA identifiers and trust-anchor extension 0xca34 into its ordinary
ClientHello/transcript. The trust-anchor IDs do not change the trusted roots or
the registered endpoint pin. H3/L4 retain the explicit QUIC adaptation:
TLS 1.3, h3 ALPN, empty session ID, QUIC transport parameters and no H2 ALPS.

Offline checks verify cipher/signature/group/version order, extension sets and
fixed extension bodies, key-share groups and lengths, ALPN, Brotli, ECH GREASE
shape and the exact ordered trust-anchor list. They normalize only permitted
randomness and extension permutation, not capability-list order. Separate
memory-only TLS/QUIC tests cover mutual authentication, wrong-pin rejection
and both directions of the new ALPS exchange. Metadata parsers distinguish
ECDSA/RSA/ML-DSA public-key identifiers from issuer signatures and reject
truncated input; parsing metadata is not certificate authentication.

Each live trial starts a fresh connection. Profile order rotates each round;
the paths run sequentially with normal CPU capabilities. The retained Chrome
131 control exists only in tests and disables the Chrome 155 additions on its
own context. The Chrome 155 trial uses the production selection after promotion.

Only the selected Consumer vault records are read. The tests never enroll,
refresh or write credentials/config, start TUN/VPN or mutate routes, WFP,
interface DNS or system proxy. L4 opens one fixed HTTPS destination through its
stream without direct fallback or redirects. Logs retain public algorithm IDs,
lengths and statuses, not raw handshakes, certificates, keys, pins, account IDs,
SNI, response headers/bodies or key logs.

## Candidate and reproduction

The initial test-only experiment was based on local `dev` commit
`d9c40a292b07340daf5354ccd9489e0768e85f36` plus uncommitted probe/native changes.
Its unit-test executable was `usque_transport-71dfbbe59a029077.exe`, SHA-256
`961a13aae0a34a33fdcd0f0452bd12595cfcbf31edd1763d46cf4a780d9f7ada`.
The local changed-source hash manifest had SHA-256
`cb39148be60ca243656950b8a94a8b8d2c9e0e33d483b444b2ee434ac4b852d8`.
The base commit alone does not identify the uncommitted experiment; this record
is not a complete archive of that intermediate candidate. Logs and manifests
remain untracked under `target/chrome155-probe/`.

After a Windows helper build, use the transport unit-test executable reported
by that build (its suffix may change):

```powershell
$env:USQUE_LIVE_CHROME155_PROBE = '1'
$env:USQUE_LIVE_CONFIG = '<authorized existing Usque config.json>'
$env:USQUE_LIVE_ENDPOINT = '162.159.199.2:443'
& '<transport test executable>' 'chrome_fingerprint_tests::live::cloudflare_observes_chrome155_h2_h3_without_tun' --exact --ignored --nocapture --test-threads=1
& '<transport test executable>' 'chrome_fingerprint_tests::l4_live::cloudflare_observes_chrome155_l4_without_tun' --exact --ignored --nocapture --test-threads=1
```

The first invocation contains 18 trials; the second contains nine. Do not
enable unrelated ignored tests. A timeout, rejection, missing algorithm or
failed control is inconclusive, not evidence that ML-DSA is required or absent.

## Final production validation

The production integration repeated the complete matrix at 05:20:55
Asia/Taipei on 2026-10-17 (2026-10-16 21:20:55 UTC): **27/27 passed**, including
27 verified pins and 27 ECDSA `0x0403` handshakes. Each cell remained 3/3.
This was a separate run from the initial test-only experiment. Its Chrome 155
trials used the production configuration without enabling a test override.

Final transport unit-test binary: `usque_transport-bcbfd1bead1fc724.exe`;
SHA-256 `974aa98778efa254d521e779a934c52944b385b1f802b18900852cfec437a013`.
The final working-tree source/fixture manifest is retained locally as
`target/chrome155-probe/production-source-manifest.json`, SHA-256
`b9b246be58b29f3e46de2009192dccaa35a7dee1df734d130dba4254b1c4ce98`.
The production candidate is the same base commit plus this uncommitted change;
the base commit alone must not be treated as the complete tested source.

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `& ./tool/build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy` | Passed |
| `& ./tool/build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test` | Passed: 1,823 tests, 13 opt-in tests ignored |
| `& ./tool/build_windows_rust_release.ps1 -Variant x64-v2` | Passed, compile only |
| `& ./tool/build_android_rust.ps1 -AbiFilter arm64-v8a -CargoAction clippy` | Passed |
| `& ./tool/build_android_rust.ps1 -CargoAction build -AbiFilter all` | Passed: arm64-v8a, armeabi-v7a, x86_64 |
| `flutter pub get --enforce-lockfile` | Passed with pinned Flutter 3.44.7 |
| `dart format --output=none --set-exit-if-changed lib test` | Passed |
| `flutter analyze --no-pub` | Passed |
| `flutter test --no-pub` | Passed: 1,147 tests |
| `& ../../tool/prepare_windows_plugin_junctions.ps1 -FlutterProject .` | Passed |
| `flutter build windows --release --no-pub --split-debug-info=build/symbols/windows` | Passed, compile only |
| `flutter build apk --debug --config-only --no-pub` | Passed, configuration only |
| `./gradlew.bat --no-daemon :app:ktlintCheck` | Passed |
| `./gradlew.bat --no-daemon :app:testDebugUnitTest :app:lintDebug` | Passed: 465 tests, zero failures/errors/skips; lint passed |
| `buf lint` and `buf format --exit-code --diff` | Passed with Buf 1.72.0 |
| `buf breaking --against '.git#ref=HEAD'` | Passed against the base commit |
| `pwsh -NoProfile -File tool/check_source.ps1` | Passed after Windows helper initialization |
| Two named Chrome 155 live tests above | Passed: 18 H2/H3 trials plus 9 L4 trials in each of two separate runs |

Flutter commands run in `apps/usque_gui`, and Gradle commands in its `android`
directory. All Cargo operations use the helpers' locked dependency settings.
The two Windows golden updates were visually reviewed: only the 131-to-155
digits changed (117 phone pixels and 330 TV pixels). The complete suite then
passed with exact image comparison.

An initial sandboxed transport run was aborted after existing loopback tests
failed; the completed normal-permission helper run above supersedes it. The
sandbox also prevented the pinned protoc from loading; the normal-permission
check used that same pinned executable successfully. No verification was
disabled, and no toolchain version was substituted.

Zero Trust, IPv6 live ingress, isolated VPN/platform lifecycle, externally
observed leaks, sustained sessions and performance labs are **not_run**.
This result applies only to the tested account, ingress, destination, network
and date; other endpoints or future service changes may choose differently.

## 中文结论

首轮默认、Chrome 131、Chrome 155 在 H2/H3/L4 的 27 次实测全部通过。
服务端握手签名均为 ECDSA P-256/SHA-256（0x0403），没有选择声明的 ML-DSA；
公钥 pin 与 TLS Finished 全部验证成功。所测 WARP 环境当前不依赖 ML-DSA 验签，
因此先替换 Chrome 155 指纹、暂缓密码库升级。此结论不代表所有端点或未来服务。
正式集成后再次实测 27/27 通过，仍全部为 ECDSA；Default 保留原有行为，
未发布的 Chrome 131 配置不做迁移或别名兼容。

---

WARP is a trademark and/or registered trademark of Cloudflare, Inc. in the United States and other jurisdictions.
