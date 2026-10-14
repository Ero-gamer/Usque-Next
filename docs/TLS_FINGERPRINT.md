# MASQUE TLS fingerprint / MASQUE TLS 指纹

The TLS fingerprint setting chooses the ClientHello preferences used when
connecting to Cloudflare WARP over HTTP/2 or HTTP/3. It is a shared network
setting, so changing accounts keeps the selection.

## Choose a profile

1. Open **Settings → Advanced network settings**.
2. In **Transport**, find **TLS fingerprint**.
3. Choose **Default** to keep the existing handshake behavior, or
   **Chrome 131** to use the fixed Chrome 131 ClientHello profile.
4. Choose **Apply changes**.

New installations and upgraded configurations use **Default** unless you
explicitly change it. Restoring network defaults stages **Default**; choose
**Apply changes** to save the reset.

For a stable active connection, applying a different fingerprint uses the normal
controlled reconnect. When disconnected, the setting is saved for the next
connection. Other connection states follow the existing
[network-settings application rules](NETWORK_SETTINGS.md#application-rules);
a saved value does not by itself confirm that the running connection uses it.
If saving fails, the page retains the draft. If the selected profile cannot
connect on your network, choose **Default**, apply it, and connect again.

If the page asks you to update the engine, the connected engine does not support
fingerprint selection. The picker is disabled and a saved Chrome selection
cannot silently connect using Default. Update the engine before using it.

When Auto connect is enabled with Chrome 131, startup waits for the engine's
capability response. Temporary query failures are retried, including with
Custom endpoints and Zero Trust accounts. Disconnect cancels that pending
automatic connection.

## Scope and limits

- **Chrome 131** is a fixed profile, not an arbitrary uTLS template editor or
  a profile that automatically tracks installed Chrome versions.
- HTTP/2 uses the Chrome 131 TLS preferences. HTTP/3 adapts them for QUIC:
  TLS 1.3, `h3` ALPN and the required QUIC transport parameters.
- Chrome 131 keeps the same cipher order on devices with and without AES
  acceleration. Default retains BoringSSL's device-dependent preferences;
  selecting Chrome does not enable unsupported CPU instructions.
- The same selection applies when Auto transport tries HTTP/3 and falls back
  to HTTP/2, and to the HTTP/3 connection used by experimental L4. It does not
  change which transport is allowed.
- The setting affects MASQUE TLS only. Registration requests, Direct DNS and
  chain-proxy TLS retain their existing behavior.
- The fingerprint does not reproduce Chrome's entire traffic behavior, QUIC
  packetization, transport parameters or HTTP SETTINGS. ECH GREASE is included
  in the Chrome profile; it is not real ECH encryption or a guarantee that SNI
  is hidden.
- WARP client credentials and the registered endpoint public-key pin remain
  mandatory. Selecting a fingerprint does not bypass authentication or pin
  verification.

The original [compatibility experiment](CHROME_FINGERPRINT_VALIDATION.md)
recorded authenticated H2 and H3 CONNECT-IP acceptance at one Consumer endpoint
on 2026-10-14. Its test counts and results belong to that recorded candidate,
account, endpoint and network. They do not guarantee every account type, endpoint
or network accepts the profile, or establish full browser impersonation, VPN
lifecycle or leak behavior.

The [implementation validation record](TLS_FINGERPRINT_IMPLEMENTATION_VALIDATION.md)
lists the separate production-source checks and unavailable environments.
The [L4 compatibility record](L4_CHROME_FINGERPRINT_VALIDATION.md) separately
verifies Consumer L4 CONNECT and an HTTPS exchange with both profiles.

## 选择与应用

在 **设置 → 高级网络设置 → 传输协议 → TLS 指纹** 中，选择 **默认** 或
**Chrome 131**，再点击 **应用修改**。这是所有账号共用的网络设置。
新安装和升级均保留默认握手行为，只有主动选择后才使用 Chrome 131。
恢复网络默认值会暂存“默认”，仍需应用修改后才保存。

连接稳定时修改指纹会按现有流程重新连接；断开时保存，供下次连接使用。
其他连接状态遵循[网络设置应用规则](NETWORK_SETTINGS.md#application-rules)。
保存成功不等于当前连接已使用新指纹；保存失败会保留草稿。若 Chrome 131
在当前网络连接失败，可切回“默认”、应用并重新连接。
若页面提示更新引擎，指纹选择器会禁用；已保存的 Chrome 配置不会在旧引擎上
悄悄改用默认指纹连接，应先更新引擎。
启用自动连接并选择 Chrome 131 时，启动会等待引擎返回能力信息；查询暂时失败
会自动重试，自定义端点和 Zero Trust 账号也适用。主动断开会取消这次等待中的
自动连接。

Chrome 131 是固定的 TLS ClientHello 配置，H3 使用符合 QUIC 要求的适配。
不论设备是否支持 AES 加速，Chrome 配置都保持相同的密码套件顺序；默认配置
继续使用 BoringSSL 根据设备能力选择的顺序，不会启用设备不支持的 CPU 指令。
自动传输模式的 H3 尝试、H2 回退及实验性 L4 的 H3 连接都使用同一选择。
它仅作用于 MASQUE TLS，不改变注册请求、直连 DNS 或链式代理的 TLS。
这不等于完整模拟 Chrome
流量，也不保证隐藏 SNI；ECH GREASE 不是真实 ECH 加密。WARP 客户端凭据认证
和注册端点公钥校验始终保留。[历史实测记录](CHROME_FINGERPRINT_VALIDATION.md)
只证明当时所测账号、端点和网络接受该配置，不能推广为所有环境兼容。

---

WARP is a trademark and/or registered trademark of Cloudflare, Inc. in the United States and other jurisdictions.
