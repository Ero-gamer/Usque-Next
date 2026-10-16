//! Reads only four records belonging to the explicitly selected Usque identity.
//! No enrollment, refresh, vault writes, OS networking changes or key logging.
use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use usque_core::{AddressFamily, AppConfig, Transport};
use usque_platform::{SecretRecord, SecretVault, WindowsCredentialVault};

use super::{Carrier, experiment_profiles};
use crate::h2::{MasqueTlsIdentity, TransportError};
use crate::socket::noop_socket_protector;

pub(super) async fn identity_from_vault(config: &AppConfig) -> MasqueTlsIdentity {
    let id = config
        .active_profile_id
        .expect("enrolled active account required");
    assert!(config.profiles.iter().any(|profile| profile.id == id));
    let vault = WindowsCredentialVault;
    async fn read(
        vault: &WindowsCredentialVault,
        id: uuid::Uuid,
        record: SecretRecord,
    ) -> zeroize::Zeroizing<Vec<u8>> {
        vault
            .get(id, record)
            .await
            .expect("Usque vault read")
            .expect("enrolled identity record required")
    }
    let private = read(&vault, id, SecretRecord::MasquePrivateKey).await;
    let pin = read(&vault, id, SecretRecord::EndpointPin).await;
    let ipv4 = read(&vault, id, SecretRecord::AssignedIpv4).await;
    let ipv6 = read(&vault, id, SecretRecord::AssignedIpv6).await;
    MasqueTlsIdentity::new(
        private,
        &pin,
        std::str::from_utf8(&ipv4)
            .expect("assigned IPv4 encoding")
            .parse()
            .expect("assigned IPv4"),
        std::str::from_utf8(&ipv6)
            .expect("assigned IPv6 encoding")
            .parse()
            .expect("assigned IPv6"),
    )
    .expect("enrolled MASQUE identity")
}

async fn attempt(
    carrier: Carrier,
    endpoint: SocketAddr,
    sni: &str,
    identity: &MasqueTlsIdentity,
    cancellation: CancellationToken,
) -> Result<(), TransportError> {
    match carrier {
        Carrier::H2 => {
            let tunnel = crate::h2::connect_h2_with_cancellation(
                endpoint,
                sni,
                identity,
                noop_socket_protector().as_ref(),
                None,
                &cancellation,
            )
            .await?;
            tunnel.shutdown().await;
        }
        Carrier::H3 => {
            let tunnel = crate::h3::connect_h3_with_cancellation(
                endpoint,
                sni,
                identity,
                crate::h3::H3ConnectSettings {
                    inner_mtu: 1280,
                    congestion_control: usque_core::CongestionControlAlgorithm::default(),
                },
                noop_socket_protector(),
                None,
                cancellation,
            )
            .await?;
            tunnel.shutdown().await;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit live WARP permission and USQUE_LIVE_CHROME_PROBE=1, USQUE_LIVE_CONFIG, USQUE_LIVE_ENDPOINT; no TUN"]
async fn cloudflare_accepts_chrome_h2_and_h3_without_tun() {
    run(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit Chrome155 WARP probe; USQUE_LIVE_CHROME155_PROBE=1 and existing config/endpoint; no TUN"]
async fn cloudflare_observes_chrome155_h2_h3_without_tun() {
    run(true).await;
}

async fn run(chrome155: bool) {
    assert_eq!(
        std::env::var(if chrome155 {
            "USQUE_LIVE_CHROME155_PROBE"
        } else {
            "USQUE_LIVE_CHROME_PROBE"
        })
        .as_deref(),
        Ok("1")
    );
    let config_path = std::env::var_os("USQUE_LIVE_CONFIG").expect("explicit config path");
    let config: AppConfig =
        serde_json::from_slice(&std::fs::read(config_path).expect("read config"))
            .expect("current app config");
    let endpoint: SocketAddr = std::env::var("USQUE_LIVE_ENDPOINT")
        .expect("explicit Cloudflare endpoint")
        .parse()
        .expect("endpoint address");
    // Bound the experiment to known WARP ingress ranges and the documented
    // shared H2/H3 port. Never scan addresses or silently switch the carrier.
    let std::net::IpAddr::V4(ip) = endpoint.ip() else {
        panic!("this experiment requires an explicit IPv4 endpoint");
    };
    let octets = ip.octets();
    assert!(octets[..2] == [162, 159] && matches!(octets[2], 192 | 197 | 198 | 199));
    assert_eq!(endpoint.port(), 443);
    let identity = super::l4_live::l4_identity(&config).await;
    let mut successful = 0;
    for carrier in [Carrier::H2, Carrier::H3] {
        let mut profiles = experiment_profiles(chrome155);
        for round in 0..3 {
            for preset in &profiles {
                let probe = preset.probe();
                let mut candidate = identity.clone().with_fingerprint(preset.core());
                candidate.fingerprint_probe = Some(probe.clone());
                let cancellation = CancellationToken::new();
                let started = Instant::now();
                let result = timeout(
                    Duration::from_secs(30),
                    attempt(
                        carrier,
                        endpoint,
                        &config.network.endpoint.sni,
                        &candidate,
                        cancellation.clone(),
                    ),
                )
                .await;
                cancellation.cancel();
                let observation = probe.snapshot();
                let profile_valid = !observation.malformed_hello
                    && observation
                        .hello
                        .as_ref()
                        .is_some_and(|hello| preset.verify(hello, carrier));
                let accepted = matches!(result, Ok(Ok(())));
                let transport = match carrier {
                    Carrier::H2 => Transport::Http2,
                    Carrier::H3 => Transport::Http3,
                };
                let failure = result
                    .as_ref()
                    .ok()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error.failure(Some(transport), Some(AddressFamily::Ipv4)));
                let http_status = match &result {
                    Ok(Err(TransportError::ConnectRejected(status))) => Some(status.as_u16()),
                    Ok(Ok(())) => Some(200),
                    _ => None,
                };
                println!(
                    "CHROME_MASQUE_PROBE {}",
                    serde_json::json!({
                        "carrier": transport,
                        "profile": preset.name(),
                        "authentication": observation.authentication_summary(),
                        "round": round + 1,
                        "elapsed_ms": started.elapsed().as_millis(),
                        "client_hello_verified": profile_valid,
                        "hello": observation.hello.as_ref().map(|hello| hello.summary()),
                        "tls_ready": observation.tls_ready,
                        "tls_version": observation.tls_version,
                        "negotiated_alpn": observation.alpn,
                        "peer_alert": observation.peer_alert,
                        "connect_ip_accepted": accepted,
                        "http_status": http_status,
                        "timeout": result.is_err(),
                        "failure_code": failure.as_ref().map(|failure| failure.code),
                        "failure_stage": failure.as_ref().map(|failure| failure.stage),
                        "tun": false
                    })
                );
                successful +=
                    usize::from(accepted && profile_valid && observation.authentication_observed());
            }
            profiles.rotate_left(1);
        }
    }
    assert_eq!(
        successful,
        if chrome155 { 18 } else { 12 },
        "all controls and Chrome trials must complete authenticated TLS and CONNECT-IP; inspect sanitized records"
    );
}
