//! Opt-in interoperability experiment; never compiled into the application.
//!
//! Observes the production Chrome 131 profile against uTLS HelloChrome_131:
//! https://github.com/refraction-networking/utls/blob/ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67/u_parrots.go
//! QUIC requires TLS 1.3, h3 ALPN and transport parameters. This does not
//! emulate Chrome's QUIC packetization or HTTP/2 and HTTP/3 SETTINGS.
//! Fingerprint setup, authentication and endpoint pinning use production code.

mod hello;
#[cfg(windows)]
mod live;

use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex};

use boring::error::ErrorStack;
use boring::ssl::{SslContext, SslContextBuilder, SslRef};

use crate::h2::MasqueTlsIdentity;
use hello::Hello;

use crate::tls_fingerprint::Carrier;

#[derive(Clone, Default)]
pub(crate) struct Observation {
    hello: Option<Hello>,
    malformed_hello: bool,
    tls_ready: bool,
    tls_version: String,
    alpn: String,
    peer_alert: Option<u8>,
}

#[derive(Clone)]
pub(crate) struct Probe {
    observation: Arc<Mutex<Observation>>,
}

impl Probe {
    fn new() -> Self {
        Self {
            observation: Arc::new(Mutex::new(Observation::default())),
        }
    }

    fn snapshot(&self) -> Observation {
        self.observation.lock().expect("probe observation").clone()
    }

    pub(crate) fn observe_messages(
        &self,
        builder: &mut SslContextBuilder,
    ) -> Result<(), ErrorStack> {
        // Context ex-data owns the callback state until the last SSL using the
        // context is destroyed. No raw handshake bytes or key log are retained.
        let index = SslContext::new_ex_index::<Arc<Mutex<Observation>>>()?;
        builder.replace_ex_data(index, Arc::clone(&self.observation));
        // SAFETY: builder owns a live SSL_CTX; its ex-data keeps the pointed-to
        // Mutex alive for every message callback, including connection teardown.
        unsafe {
            boring_sys::SSL_CTX_set_msg_callback(builder.as_ptr(), Some(observe_message));
            boring_sys::SSL_CTX_set_msg_callback_arg(
                builder.as_ptr(),
                Arc::as_ptr(&self.observation).cast_mut().cast(),
            );
        }
        Ok(())
    }
    pub(crate) fn observe_tls_done(&self, ssl: &SslRef) {
        if let Ok(mut observation) = self.observation.lock() {
            observation.tls_ready = true;
            observation.tls_version = ssl.version_str().to_owned();
            observation.alpn =
                String::from_utf8_lossy(ssl.selected_alpn_protocol().unwrap_or_default())
                    .into_owned();
        }
    }
}

unsafe extern "C" fn observe_message(
    write: c_int,
    _version: c_int,
    content_type: c_int,
    buffer: *const c_void,
    length: usize,
    _ssl: *mut boring_sys::SSL,
    arg: *mut c_void,
) {
    if buffer.is_null() || arg.is_null() || length == 0 || length > 65_536 {
        return;
    }
    // SAFETY: BoringSSL supplies `length` readable bytes for this callback.
    // The SSL_CTX ex-data owns arg's Arc for the entire SSL lifetime.
    let (message, state) = unsafe {
        (
            std::slice::from_raw_parts(buffer.cast::<u8>(), length),
            &*arg.cast::<Mutex<Observation>>(),
        )
    };
    let Ok(mut observation) = state.lock() else {
        return;
    };
    if write == 1 && content_type == 22 && message[0] == 1 && observation.hello.is_none() {
        observation.hello = Hello::parse(message);
        observation.malformed_hello = observation.hello.is_none();
    }
    if write == 0 && content_type == 21 && message.len() == 2 {
        observation.peer_alert = Some(message[1]);
    }
}

fn fixture_identity(probe: Probe, profile: usque_core::TlsFingerprint) -> MasqueTlsIdentity {
    let client = usque_core::MasqueKeyPair::generate();
    let peer = usque_core::MasqueKeyPair::generate();
    let mut identity = MasqueTlsIdentity::new(
        client.private_sec1_der().unwrap(),
        &peer.public_spki_der().unwrap(),
        "192.0.2.2".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    )
    .unwrap();
    identity = identity.with_fingerprint(profile);
    identity.fingerprint_probe = Some(probe);
    identity
}

async fn capture_h2_client_hello(profile: usque_core::TlsFingerprint) -> Hello {
    use tokio::io::AsyncReadExt;
    let probe = Probe::new();
    let identity = fixture_identity(probe.clone(), profile);
    let connector = crate::h2::fingerprint_test_connector(&identity).unwrap();
    let (client, mut peer) = tokio::io::duplex(16_384);
    let handshake = tokio::spawn(async move {
        {
            let mut config = connector.configure().unwrap();
            crate::tls_fingerprint::configure_h2_connection(&mut config, profile).unwrap();
            tokio_boring::connect(config, "example.com", client).await
        }
    });
    let mut header = [0; 5];
    peer.read_exact(&mut header).await.unwrap();
    let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    peer.read_exact(&mut body).await.unwrap();
    drop(peer);
    assert!(handshake.await.unwrap().is_err());
    let observed = probe.snapshot();
    assert!(!observed.malformed_hello);
    let hello = observed.hello.expect("outgoing ClientHello observed");
    assert_eq!(hello, Hello::parse(&body).expect("wire ClientHello"));
    for length in 0..body.len() {
        assert!(Hello::parse(&body[..length]).is_none());
    }
    hello
}

fn capture_h3_client_hello(profile: usque_core::TlsFingerprint) -> Hello {
    let probe = Probe::new();
    let identity = fixture_identity(probe.clone(), profile);
    let (mut config, _) = crate::h3::quic_config(&identity, 1350).unwrap();
    let scid = quiche::ConnectionId::from_ref(&[0x22; 20]);
    let mut connection = quiche::connect(
        Some("example.com"),
        &scid,
        "127.0.0.1:12000".parse().unwrap(),
        "127.0.0.1:12001".parse().unwrap(),
        &mut config,
    )
    .unwrap();
    let mut wire = [0; 1500];
    connection.send(&mut wire).unwrap();
    let observed = probe.snapshot();
    assert!(!observed.malformed_hello);
    observed.hello.expect("outgoing QUIC ClientHello observed")
}

#[tokio::test]
async fn h2_chrome_131_client_hello_is_verified_without_network() {
    capture_h2_client_hello(usque_core::TlsFingerprint::Chrome131)
        .await
        .verify_chrome(Carrier::H2)
        .expect("Chrome 131 wire profile");
}

#[test]
fn h3_chrome_tls_client_hello_is_verified_without_network() {
    capture_h3_client_hello(usque_core::TlsFingerprint::Chrome131)
        .verify_chrome(Carrier::H3)
        .expect("Chrome TLS preferences adapted to QUIC");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[tokio::test]
async fn no_aes_profile_child() {
    if std::env::var_os("USQUE_TEST_TLS_NO_AES").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    boring::init();
    // SAFETY: this read-only capability query takes no arguments. The parent
    // supplied the CPU mask before process startup; no global environment is
    // changed concurrently with BoringSSL initialization or other tests.
    assert_eq!(unsafe { boring_sys::EVP_has_aes_hardware() }, 0);

    for profile in [
        usque_core::TlsFingerprint::Default,
        usque_core::TlsFingerprint::Chrome131,
    ] {
        for (carrier, hello) in [
            (Carrier::H2, capture_h2_client_hello(profile).await),
            (Carrier::H3, capture_h3_client_hello(profile)),
        ] {
            if profile == usque_core::TlsFingerprint::Chrome131 {
                hello
                    .verify_chrome(carrier)
                    .expect("fixed Chrome profile without AES hardware");
            } else {
                let tls13: Vec<_> = hello
                    .ciphers
                    .iter()
                    .copied()
                    .filter(|value| (0x1301..=0x1303).contains(value))
                    .collect();
                assert_eq!(
                    tls13,
                    [0x1303, 0x1301, 0x1302],
                    "Default retains native CPU-dependent ordering for {carrier:?}"
                );
                let grease = |value: &u16| value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff;
                assert!(!hello.ciphers.iter().any(grease));
                assert!(!hello.extensions.iter().any(grease));
                assert!(!hello.extensions.contains(&17513));
                assert!(!hello.extensions.contains(&65037));
                assert!(hello.compression.is_empty());
            }
        }
    }
    // Prove the exact child test ran; an accidentally renamed filter must not
    // pass merely because libtest reports success with zero matching tests.
    let marker = std::env::var_os("USQUE_TEST_TLS_NO_AES_RESULT").expect("parent result path");
    std::fs::write(marker, b"h2,h3:chrome,default").unwrap();
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn chrome_and_default_profiles_without_aes_hardware() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct ReapChild(Child);
    impl Drop for ReapChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("verified");
    let mut child = ReapChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "chrome_fingerprint_tests::no_aes_profile_child",
                "--nocapture",
                "--test-threads=1",
            ])
            // Disable AES-NI in this child only. The child also asserts that
            // BoringSSL reports no AES hardware; no capability bits are added.
            .env("OPENSSL_ia32cap", "~0x200000000000000")
            .env("USQUE_TEST_TLS_NO_AES", "1")
            .env("USQUE_TEST_TLS_NO_AES_RESULT", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated no-AES profile test failed: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "isolated no-AES profile test timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read(marker).unwrap(), b"h2,h3:chrome,default");
}

#[test]
fn malformed_client_hello_is_rejected_without_panicking() {
    for length in 0..256 {
        assert!(Hello::parse(&vec![0; length]).is_none());
    }
    assert!(Hello::parse(&[1, 0, 0, 40, 3, 3]).is_none());
}
