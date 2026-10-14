# L4 Chrome TLS fingerprint validation

On 2026-10-14 at 14:26 Asia/Singapore (06:26 UTC), the selected Consumer WARP
identity completed L4 CONNECT and an HTTPS exchange with both Default and
Chrome 131 TLS fingerprints. This is separate from the earlier
[CONNECT-IP experiment](TLS_FINGERPRINT_IMPLEMENTATION_VALIDATION.md).

## Measured result

| Process CPU capabilities | Default | Chrome 131 |
| --- | --- | --- |
| Normal | 3/3 | 3/3 |
| AES-NI masked for the test process | 3/3 | 3/3 |

All 12 final attempts passed each of these steps:

1. Connect to WARP ingress `162.159.199.2:443` with the production L4 client,
   the registered client identity and endpoint SPKI pin. Consumer L4 selects
   `consumer-masque-proxy.cloudflareclient.com` as SNI.
2. Complete TLS 1.3 with ALPN `h3`. Chrome trials also verify the actual outgoing
   ClientHello against the fixed Chrome 131 profile adapted for QUIC.
3. Receive an accepted classic HTTP/3 CONNECT stream to `1.1.1.1:443`.
   The production actor delivers this stream only after a final **2xx** response.
   The probe does not capture the exact successful CONNECT status, so this
   result is deliberately recorded as 2xx rather than assuming 200.
4. Perform a second TLS handshake over that L4 stream, verifying the public
   certificate for `one.one.one.one` with the pinned WebPKI root bundle.
5. Send `HEAD / HTTP/1.1` and receive **HTTP 200** over that verified HTTPS
   connection. This is the application response, distinct from CONNECT status.
6. Cancel and join the L4 client within the cleanup deadline.

Each trial starts a fresh L4 client. Control and Chrome order is reversed in
the middle round. The AES-NI-masked run uses process-local
`OPENSSL_ia32cap=~0x200000000000000`; Chrome retains its fixed cipher order.
The normal and masked runs are independent processes, not changes to CPU or
system configuration.

## Scope, privacy and initial probe correction

The probe reads the selected identity's private key, endpoint pin, assigned
addresses and identity metadata from the existing vault. It verifies the saved
provider boundary and is explicitly limited to Consumer credentials. It does
not enroll, refresh, replace or revoke credentials, or save app configuration.

It uses `L4Client` and the shared production H3/TLS implementation directly.
There is no CONNECT-IP/H2 fallback, TUN, local proxy listener, route, WFP,
interface-DNS or system-proxy mutation. The fixed HTTPS destination is opened
only through the L4 stream; it is not reached through a direct-connect fallback.
Redirects are not followed. At most 8 KiB of response headers are held temporarily;
only status and byte count are reported, not headers, bodies, exit addresses,
keys, pins, account identifiers, client randoms or key-share bytes.

The first probe incorrectly used the supervisor's asynchronously updated
`connect_verified` snapshot as an immediate success barrier. Four of its six
trials stopped before HTTPS even though CONNECT had returned a stream and
`connect_successes` was already one. This was a probe observation error, not a
server rejection. The final probe uses the actual successful CONNECT return,
then checks the HTTPS exchange and recorded CONNECT success. The initial six
trials are excluded from the final 12/12 matrix. Production code was unchanged.

This establishes compatibility for the tested Consumer account, ingress,
destination, network and date. It does not establish Zero Trust compatibility,
all endpoints or destinations, L4 over H2, full Chrome traffic impersonation,
throughput, long-lived session stability, VPN lifecycle or leak behavior.

## Candidate and reproducible command

Production source: `fcfcacee08bf5391b6fc0c356275955478ccacf9` on local `dev`.
The working tree adds a Windows-only ignored L4 probe and a small HTTP response
parser test, reusing the existing test-only vault loader. The base commit alone
does not identify these uncommitted test additions; this record is not a complete
source archive.

Executed unit-test binary: `target/debug/deps/usque_transport-bcbfd1bead1fc724.exe`.
SHA-256: `885768cc54827dd9e716ec6d0b9bfcc424ec185680138cca6e67e03312b8f23e`.

After an authorized local build, run only the named ignored test. Use the
transport unit-test executable reported by that build; its suffix may change.
Run each mode in a fresh PowerShell process, with an explicitly authorized
existing config and ingress:

```powershell
$env:USQUE_LIVE_L4_CHROME_PROBE = '1'
$env:USQUE_LIVE_CONFIG = '<authorized local Usque config.json path>'
$env:USQUE_LIVE_ENDPOINT = '162.159.199.2:443'
# For the masked process only:
# $env:OPENSSL_ia32cap = '~0x200000000000000'
& .\target\debug\deps\usque_transport-bcbfd1bead1fc724.exe 'chrome_fingerprint_tests::l4_live::cloudflare_accepts_chrome_l4_and_transfers_https_without_tun' --exact --ignored --nocapture --test-threads=1
```

Each named invocation passed as one test with six successful L4/HTTPS trials.
No other ignored tests were enabled.

## Validation

| Command from repository root | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction clippy` | Passed |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2 -CargoAction test` | Passed: 1,757 tests; 10 opt-in tests ignored |
| `& .\tool\build_windows_rust_release.ps1 -Variant x64-v2` | Passed; compile only |
| Named L4 live test, normal process | Passed: 6/6 |
| Named L4 live test, AES-NI-masked process | Passed: 6/6 |
| `python tool/check_repository_policy.py` | Passed using the verified Python 3.12 executable |
| `git diff --check` | Passed |

Changes are limited to Windows test code and documentation. Android/Flutter
sources and production transport code were not changed. Zero Trust live tests,
Windows snapshot VM, dedicated Android device, external leak observation and
performance lab checks remain **not_run**. No installation or publication was
performed.

## 中文结论

本次直接验证了 **L4 + Chrome 131**。正常和屏蔽 AES-NI 的进程分别进行默认/Chrome
三轮对照，最终 **12/12 成功**：外层 TLS 1.3 与 H3、L4 CONNECT 2xx、流内 HTTPS
证书验证及应用 HTTP 200 均通过。结果仅覆盖所测 Consumer 账号、端点及网络，
不能推广为所有账号或 Zero Trust 均已验证。没有启动 VPN/TUN 或修改系统网络设置。

---

WARP is a trademark and/or registered trademark of Cloudflare, Inc. in the United States and other jurisdictions.
