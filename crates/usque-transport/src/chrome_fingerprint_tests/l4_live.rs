//! Explicit no-TUN L4 experiment. Reads the selected identity; never refreshes,
//! enrolls, writes credentials/config, follows redirects, or logs response data.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use usque_core::{
    AddressFamily, AppConfig, DataPlaneMode, EndpointSelection, IdentityMetadata, IdentityProvider,
    IpPolicy, Profile, Transport, TransportPolicy,
};
use usque_platform::{SecretRecord, SecretVault, WindowsCredentialVault};

use super::{Carrier, experiment_profiles};
use crate::h2::MasqueTlsIdentity;
use crate::l4::L4Client;
use crate::socket::noop_socket_protector;
use crate::tcp::{DialError, FlowClass, TcpDialer, TcpTarget};

#[derive(Default)]
struct ResultState {
    session_ready: bool,
    connect_accepted: bool,
    connect_rejected_status: Option<u16>,
    connect_error: Option<DialError>,
    inner_tls_verified: bool,
    response_status: Option<u16>,
    response_header_bytes: usize,
    stage: &'static str,
}

async fn exchange_https(
    client: &L4Client,
    deadline: Instant,
    cancellation: &CancellationToken,
    state: &mut ResultState,
) -> Result<(), ()> {
    state.stage = "l4_connect";
    // A single fixed public destination; there is no direct-connect fallback.
    let stream = client
        .connect(
            TcpTarget::new("1.1.1.1", 443).unwrap(),
            deadline,
            cancellation,
            FlowClass::Business,
        )
        .await
        .map_err(|error| {
            if let DialError::Rejected(status) = error {
                state.connect_rejected_status = Some(status);
            }
            state.connect_error = Some(error);
        })?;
    // The production actor only delivers a stream after a final 2xx response.
    // The supervisor's connect_verified snapshot is updated asynchronously,
    // so it is not a barrier for the already-delivered CONNECT result.
    state.connect_accepted = true;

    state.stage = "inner_tls";
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut stream = connector
        .connect("one.one.one.one".try_into().unwrap(), stream)
        .await
        .map_err(|_| ())?;
    state.inner_tls_verified = true;
    state.stage = "https_response";
    stream
        .write_all(b"HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())?;

    // Retain at most 8 KiB temporarily. Never print headers, body or exit IP.
    let mut headers = Vec::new();
    while headers.len() < 8192 {
        let mut chunk = [0; 1024];
        let limit = chunk.len().min(8192 - headers.len());
        let n = stream.read(&mut chunk[..limit]).await.map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        headers.extend_from_slice(&chunk[..n]);
        if let Some(end) = headers.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            state.response_header_bytes = end + 4;
            state.response_status = http_status(&headers[..end + 4]);
            if state
                .response_status
                .is_some_and(|status| (200..400).contains(&status))
            {
                state.stage = "complete";
                return Ok(());
            }
            return Err(());
        }
    }
    Err(())
}

fn http_status(headers: &[u8]) -> Option<u16> {
    if !headers.ends_with(b"\r\n\r\n") {
        return None;
    }
    let line = headers.split(|byte| *byte == b'\n').next()?;
    let mut parts = std::str::from_utf8(line).ok()?.split_ascii_whitespace();
    if !matches!(parts.next()?, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    status
        .parse()
        .ok()
        .filter(|status| (100..600).contains(status))
}

#[test]
fn application_status_requires_complete_valid_http_headers() {
    assert_eq!(http_status(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
    assert_eq!(
        http_status(b"HTTP/1.0 301 Moved\r\nX-Test: 1\r\n\r\n"),
        Some(301)
    );
    for invalid in [
        b"HTTP/1.1 200 OK\r\n".as_slice(),
        b"HTTP/2 200 OK\r\n\r\n",
        b"HTTP/1.1 2x0 OK\r\n\r\n",
        b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 099 Invalid\r\n\r\n",
    ] {
        assert_eq!(http_status(invalid), None);
    }
}

pub(super) async fn l4_identity(config: &AppConfig) -> MasqueTlsIdentity {
    let id = config.active_profile_id.expect("active identity required");
    let metadata = WindowsCredentialVault
        .get(id, SecretRecord::IdentityMetadata)
        .await
        .expect("read selected identity metadata")
        .expect("this experiment requires explicit enrolled identity metadata");
    let metadata = IdentityMetadata::from_json(&metadata).expect("valid identity metadata");
    assert!(
        config
            .identity_bindings
            .get(&id)
            .is_none_or(|provider| provider == &metadata.provider),
        "identity provider must match its saved boundary"
    );
    assert!(
        matches!(metadata.provider, IdentityProvider::Consumer),
        "this experiment is scoped to the selected Consumer identity"
    );
    let mut identity = super::live::identity_from_vault(config).await;
    identity.provider = Some(metadata.provider);
    identity.entitlement = metadata.entitlement;
    identity
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit L4 permission and USQUE_LIVE_L4_CHROME_PROBE=1, USQUE_LIVE_CONFIG, USQUE_LIVE_ENDPOINT; no TUN"]
async fn cloudflare_accepts_chrome_l4_and_transfers_https_without_tun() {
    run(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit Chrome155 WARP probe; USQUE_LIVE_CHROME155_PROBE=1 and existing config/endpoint; no TUN"]
async fn cloudflare_observes_chrome155_l4_without_tun() {
    run(true).await;
}

async fn run(chrome155: bool) {
    assert_eq!(
        std::env::var(if chrome155 {
            "USQUE_LIVE_CHROME155_PROBE"
        } else {
            "USQUE_LIVE_L4_CHROME_PROBE"
        })
        .as_deref(),
        Ok("1")
    );
    let config_path = std::env::var_os("USQUE_LIVE_CONFIG").expect("explicit config path");
    let config: AppConfig =
        serde_json::from_slice(&std::fs::read(config_path).expect("read config"))
            .expect("current app config");
    let endpoint: SocketAddr = std::env::var("USQUE_LIVE_ENDPOINT")
        .expect("explicit WARP endpoint")
        .parse()
        .expect("endpoint address");
    let IpAddr::V4(ip) = endpoint.ip() else {
        panic!("this experiment requires an explicit IPv4 endpoint");
    };
    let octets = ip.octets();
    assert!(octets[..2] == [162, 159] && matches!(octets[2], 192 | 197 | 198 | 199));
    assert_eq!(endpoint.port(), 443);
    let identity = l4_identity(&config).await;
    let mut successful = 0;
    let mut profiles = experiment_profiles(chrome155);
    for round in 0..3 {
        for preset in &profiles {
            let probe = preset.probe();
            let mut candidate = identity.clone();
            candidate.fingerprint_probe = Some(probe.clone());
            let mut profile = Profile {
                data_plane: DataPlaneMode::L4Proxy,
                transport: TransportPolicy::Http3,
                ip_policy: IpPolicy::Ipv4Only,
                tls_fingerprint: preset.core(),
                ..Default::default()
            };
            profile.endpoint.selection = EndpointSelection::Custom;
            profile.endpoint.ipv4 = ip;
            profile.endpoint.port = endpoint.port();
            profile.frontends.tunnel = false;
            profile.frontends.socks5 = false;
            profile.frontends.http = false;
            let cancellation = CancellationToken::new();
            let _cancel_on_drop = cancellation.clone().drop_guard();
            let started = Instant::now();
            let deadline = started + Duration::from_secs(30);
            let mut state = ResultState {
                stage: "l4_session",
                ..Default::default()
            };
            let mut failure = None;
            let mut timed_out = false;
            let mut cleanup_complete = None;
            let mut metrics = None;
            match timeout_at(
                deadline,
                L4Client::start(
                    profile,
                    candidate,
                    noop_socket_protector(),
                    None,
                    crate::telemetry::ConnectionTelemetry::default(),
                    Arc::default(),
                    &cancellation,
                ),
            )
            .await
            {
                Ok(Ok(client)) => {
                    state.session_ready = true;
                    timed_out = timeout_at(
                        deadline,
                        exchange_https(&client, deadline, &cancellation, &mut state),
                    )
                    .await
                    .is_err();
                    metrics = Some(client.snapshot());
                    cancellation.cancel();
                    cleanup_complete = Some(
                        timeout(Duration::from_secs(5), client.shutdown())
                            .await
                            .is_ok(),
                    );
                }
                Ok(Err(error)) => {
                    failure = Some(error.failure(Some(Transport::Http3), Some(AddressFamily::Ipv4)))
                }
                Err(_) => timed_out = true,
            }
            cancellation.cancel();
            let observed = probe.snapshot();
            let profile_valid = !observed.malformed_hello
                && observed
                    .hello
                    .as_ref()
                    .is_some_and(|hello| preset.verify(hello, Carrier::H3));
            let accepted = state.stage == "complete"
                && state.connect_accepted
                && state.inner_tls_verified
                && metrics
                    .as_ref()
                    .is_some_and(|metrics| metrics.connect_successes > 0)
                && profile_valid
                && observed.authentication_observed()
                && observed.alpn == "h3"
                && cleanup_complete == Some(true)
                && !timed_out;
            println!(
                "CHROME_L4_PROBE {}",
                serde_json::json!({
                    "profile": preset.name(),
                    "authentication": observed.authentication_summary(),
                    "round": round + 1, "elapsed_ms": started.elapsed().as_millis(),
                    "client_hello_verified": profile_valid, "hello": observed.hello.as_ref().map(|hello| hello.summary()),
                    "tls_ready": observed.tls_ready, "tls_version": observed.tls_version, "alpn": observed.alpn,
                    "peer_alert": observed.peer_alert, "session_ready": state.session_ready,
                    "connect_accepted_2xx": state.connect_accepted, "connect_rejected_status": state.connect_rejected_status,
                    "connect_error": state.connect_error.map(|error| error.to_string()),
                    "connect_successes": metrics.as_ref().map(|metrics| metrics.connect_successes),
                    "inner_tls_verified": state.inner_tls_verified, "application_http_status": state.response_status,
                    "application_header_bytes": state.response_header_bytes, "stage": state.stage,
                    "failure_code": failure.as_ref().map(|failure| failure.code),
                    "failure_stage": failure.as_ref().map(|failure| failure.stage),
                    "timeout": timed_out, "cleanup_complete": cleanup_complete, "success": accepted,
                    "tun": false, "connect_ip": false
                })
            );
            successful += usize::from(accepted);
        }
        profiles.rotate_left(1);
    }
    assert_eq!(
        successful,
        if chrome155 { 9 } else { 6 },
        "all L4 controls and Chrome trials must accept CONNECT and transfer verified HTTPS; inspect sanitized records"
    );
}
