//! Explicit Deep Doctor probes; no CONNECT-IP, resolver discovery, or OS mutation.
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use usque_core::{DirectDnsMode, DirectDnsSettings, IpPolicy, Profile};

use crate::{
    DirectDnsError, DirectDnsQueryContext, DirectDnsResolver, MasqueTlsIdentity,
    NetworkQualityTelemetry, SocketProtector, TransportError,
};

pub const PROBE_IO_TIMEOUT: Duration = Duration::from_millis(3_800);

/// Allowlisted results only, never remote errors or identifying data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProbeResult {
    Passed { milliseconds: u64 },
    NotApplicable,
    Failed,
    TimedOut,
    Cancelled,
    NetworkChanged,
}

/// Retry eligibility is internal to the probe runner. The public diagnostic
/// contract intentionally keeps the same compact, allowlisted result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H3ProbeTerminal {
    PinMismatch,
    Identity,
    Protection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H3ProbeOutcome {
    Complete(NetworkProbeResult),
    Terminal(H3ProbeTerminal),
}

impl H3ProbeOutcome {
    pub(crate) fn public_result(self) -> NetworkProbeResult {
        match self {
            Self::Complete(result) => result,
            Self::Terminal(_) => NetworkProbeResult::Failed,
        }
    }
}

impl From<NetworkProbeResult> for H3ProbeOutcome {
    fn from(result: NetworkProbeResult) -> Self {
        Self::Complete(result)
    }
}

pub async fn probe_encrypted_dns(
    settings: &DirectDnsSettings,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
) -> NetworkProbeResult {
    if settings.mode == DirectDnsMode::PhysicalSystem {
        return NetworkProbeResult::NotApplicable;
    }
    if cancellation.is_cancelled() {
        return NetworkProbeResult::Cancelled;
    }
    let started = Instant::now();
    let lifetime = cancellation.child_token();
    let _cancel_on_drop = lifetime.clone().drop_guard();
    let resolver = match DirectDnsResolver::new(
        settings,
        Arc::clone(&protector),
        NetworkQualityTelemetry::default(),
        &lifetime,
    ) {
        Ok(resolver) => resolver,
        Err(_) => return NetworkProbeResult::Failed,
    };
    run_dns_probe(resolver, protector, cancellation, lifetime, started).await
}

pub(crate) async fn run_dns_probe(
    resolver: Arc<DirectDnsResolver>,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
    lifetime: CancellationToken,
    started: Instant,
) -> NetworkProbeResult {
    let _cancel_on_drop = lifetime.clone().drop_guard();
    let generation = protector.network_generation().unwrap_or_default();
    // A reserved, fixed name, never a user's query. NXDOMAIN is a valid reply.
    let query = Bytes::from_static(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x07invalid\x00\x00\x01\x00\x01");
    let deadline = started + PROBE_IO_TIMEOUT;
    let outcome = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(DirectDnsError::Cancelled),
        reply = timeout_at(deadline, resolver.query(query, DirectDnsQueryContext { network_generation: generation, deadline })) =>
            reply.unwrap_or(Err(DirectDnsError::Timeout)),
    };
    lifetime.cancel();
    // A dedicated pool avoids changing or clearing any business DNS pool.
    // Wait for actual I/O destruction, not only for a driver abort request.
    let cleaned = resolver.close_probe_pool().await;
    if cancellation.is_cancelled() {
        return NetworkProbeResult::Cancelled;
    }
    if protector.network_generation().unwrap_or_default() != generation {
        return NetworkProbeResult::NetworkChanged;
    }
    if !cleaned {
        return NetworkProbeResult::Failed;
    }
    match outcome {
        Ok(_) => NetworkProbeResult::Passed {
            milliseconds: elapsed_ms(started),
        },
        Err(DirectDnsError::Timeout | DirectDnsError::Busy) => NetworkProbeResult::TimedOut,
        Err(DirectDnsError::Cancelled) => NetworkProbeResult::Cancelled,
        Err(DirectDnsError::NetworkChanged) => NetworkProbeResult::NetworkChanged,
        Err(_) => NetworkProbeResult::Failed,
    }
}

/// Caller must hold its connection-lifecycle exclusion while disconnected.
/// This completes only the authenticated QUIC handshake, with no HTTP/3 or
/// CONNECT-IP stream ever constructed, and closes the socket before its lease.
pub async fn probe_h3_handshake(
    endpoint: SocketAddr,
    sni: &str,
    identity: &MasqueTlsIdentity,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
) -> NetworkProbeResult {
    crate::h3::diagnostic::handshake(endpoint, sni, identity, protector, cancellation)
        .await
        .public_result()
}

/// The same family preference and forced-family policy as normal connection
/// selection. No resolver lookup or endpoint discovery is performed.
pub fn h3_probe_endpoints(profile: &Profile) -> Vec<SocketAddr> {
    // Preset discovery requires authenticated tier and physical DNS. This
    // synchronous diagnostic must never probe the dormant manual IPv6 field.
    if profile.endpoint.preset_region.is_some() {
        return Vec::new();
    }
    let (v4, v6) = if profile.endpoint.selection == usque_core::EndpointSelection::Automatic {
        // Diagnostics stay bounded to one common endpoint per family. This
        // pair is eligible for both Free and Plus authenticated identities.
        usque_core::AutomaticEndpointPolicy::for_profile(
            profile,
            usque_core::EndpointPool::WarpPlus,
        )
        .representative_pair()
    } else {
        (
            profile.endpoint.ipv4_socket(),
            profile.endpoint.ipv6_socket(),
        )
    };
    match profile.ip_policy {
        IpPolicy::Ipv4Only => vec![v4],
        IpPolicy::Ipv6Only => vec![v6],
        IpPolicy::PreferIpv4 => vec![v4, v6],
        IpPolicy::Auto | IpPolicy::PreferIpv6 => vec![v6, v4],
    }
}

/// Preset-aware discovery with the same authenticated tier and physical DNS
/// authorization as a connection. No tunnel is constructed.
pub async fn h3_probe_endpoints_resolved(
    profile: &Profile,
    identity: &MasqueTlsIdentity,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
) -> Result<Vec<SocketAddr>, NetworkProbeResult> {
    if profile.endpoint.preset_region.is_none() {
        return Ok(h3_probe_endpoints(profile));
    }
    let generation = protector.network_generation().unwrap_or_default();
    let resolution = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(NetworkProbeResult::Cancelled),
        result = crate::endpoint_preset::resolve(profile, identity, &protector) => result,
    };
    if protector.network_generation().unwrap_or_default() != generation {
        return Err(NetworkProbeResult::NetworkChanged);
    }
    let mut endpoints = match resolution {
        Ok(resolved) => resolved.candidates.into_iter().take(1).collect::<Vec<_>>(),
        Err(error) if crate::endpoint_preset::may_fallback(profile, &error) => Vec::new(),
        Err(TransportError::UnderlyingNetworkChanged) => {
            return Err(NetworkProbeResult::NetworkChanged);
        }
        Err(_) => return Err(NetworkProbeResult::Failed),
    };
    if profile.ip_policy == IpPolicy::PreferIpv6 {
        endpoints.push(profile.endpoint.ipv4_socket());
    }
    Ok(endpoints)
}

/// Serial, at-most-two-family handshake checks within one 3.8 second deadline.
/// The first socket/lease is destroyed before an alternate can be opened.
pub async fn probe_h3_handshake_candidates(
    endpoints: &[SocketAddr],
    sni: &str,
    identity: &MasqueTlsIdentity,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
) -> NetworkProbeResult {
    let generation = protector.network_generation();
    let candidates = endpoints
        .iter()
        .copied()
        .take(2)
        .filter(|endpoint| protector.endpoint_family_available(*endpoint) != Some(false))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return if cancellation.is_cancelled() {
            NetworkProbeResult::Cancelled
        } else {
            NetworkProbeResult::Failed
        };
    }
    run_h3_candidates(&candidates, cancellation.clone(), |endpoint| {
        let protector = Arc::clone(&protector);
        let cancellation = cancellation.clone();
        async move {
            if protector.network_generation() != generation {
                return NetworkProbeResult::NetworkChanged.into();
            }
            let result = crate::h3::diagnostic::handshake(
                endpoint,
                sni,
                identity,
                protector.clone(),
                cancellation,
            )
            .await;
            if protector.network_generation() != generation {
                NetworkProbeResult::NetworkChanged.into()
            } else {
                result
            }
        }
    })
    .await
}

async fn run_h3_candidates<F, Fut>(
    endpoints: &[SocketAddr],
    cancellation: CancellationToken,
    mut probe: F,
) -> NetworkProbeResult
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = H3ProbeOutcome>,
{
    let started = Instant::now();
    let deadline = started + PROBE_IO_TIMEOUT;
    let mut timed_out = false;
    for (index, endpoint) in endpoints.iter().copied().enumerate() {
        if cancellation.is_cancelled() {
            return NetworkProbeResult::Cancelled;
        }
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return NetworkProbeResult::TimedOut;
        }
        let attempt_deadline = now + remaining / (endpoints.len() - index) as u32;
        let outcome = tokio::select! {
            biased;
            _ = cancellation.cancelled() => NetworkProbeResult::Cancelled.into(),
            result = timeout_at(attempt_deadline, probe(endpoint)) => result.unwrap_or(NetworkProbeResult::TimedOut.into()),
        };
        let outcome = match outcome {
            H3ProbeOutcome::Complete(outcome) => outcome,
            H3ProbeOutcome::Terminal(_) => return NetworkProbeResult::Failed,
        };
        match outcome {
            NetworkProbeResult::Passed { .. } => {
                return NetworkProbeResult::Passed {
                    milliseconds: elapsed_ms(started),
                };
            }
            NetworkProbeResult::Failed => {}
            NetworkProbeResult::TimedOut => timed_out = true,
            other => return other,
        }
    }
    if timed_out {
        NetworkProbeResult::TimedOut
    } else {
        NetworkProbeResult::Failed
    }
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn diagnostic_family_order_matches_normal_policy_and_never_expands_forced_families() {
        for (policy, families) in [
            (IpPolicy::Auto, vec![false, true]),
            (IpPolicy::PreferIpv6, vec![false, true]),
            (IpPolicy::PreferIpv4, vec![true, false]),
            (IpPolicy::Ipv4Only, vec![true]),
            (IpPolicy::Ipv6Only, vec![false]),
        ] {
            let profile = Profile {
                ip_policy: policy,
                ..Profile::default()
            };
            assert_eq!(
                h3_probe_endpoints(&profile)
                    .iter()
                    .map(SocketAddr::is_ipv4)
                    .collect::<Vec<_>>(),
                families
            );
        }
    }

    struct ActiveProbe(Arc<AtomicUsize>);
    impl Drop for ActiveProbe {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn alternate_probe_gets_budget_and_first_probe_is_closed_before_fallback() {
        let endpoints = h3_probe_endpoints(&Profile::default());
        let active = Arc::new(AtomicUsize::new(0));
        let result = run_h3_candidates(&endpoints, CancellationToken::new(), |endpoint| {
            let active = active.clone();
            async move {
                assert_eq!(active.fetch_add(1, Ordering::AcqRel), 0);
                let _guard = ActiveProbe(active);
                if endpoint.is_ipv6() {
                    std::future::pending().await
                } else {
                    NetworkProbeResult::Passed { milliseconds: 0 }.into()
                }
            }
        })
        .await;
        assert_eq!(
            result,
            NetworkProbeResult::Passed {
                milliseconds: 1_900
            }
        );
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn terminal_ipv6_handshake_never_becomes_a_successful_ipv4_diagnosis() {
        let endpoints = [
            "[2001:db8::8]:443".parse().unwrap(),
            "192.0.2.8:443".parse().unwrap(),
        ];
        for terminal in [
            H3ProbeTerminal::PinMismatch,
            H3ProbeTerminal::Identity,
            H3ProbeTerminal::Protection,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let active = Arc::new(AtomicUsize::new(0));
            let result = run_h3_candidates(&endpoints, CancellationToken::new(), |endpoint| {
                let calls = calls.clone();
                let active = active.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    let _lease = ActiveProbe(active);
                    if endpoint.is_ipv6() {
                        H3ProbeOutcome::Terminal(terminal)
                    } else {
                        NetworkProbeResult::Passed { milliseconds: 0 }.into()
                    }
                }
            })
            .await;
            assert_eq!(result, NetworkProbeResult::Failed, "{terminal:?}");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "{terminal:?} must stop before IPv4"
            );
            assert_eq!(
                active.load(Ordering::SeqCst),
                0,
                "failed candidate releases its lease"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_deadline_and_cancellation_are_global_not_per_family() {
        let endpoints = h3_probe_endpoints(&Profile::default());
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        assert_eq!(
            run_h3_candidates(&endpoints, CancellationToken::new(), |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::pending()
            })
            .await,
            NetworkProbeResult::TimedOut
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(started.elapsed(), PROBE_IO_TIMEOUT);
        let stop = CancellationToken::new();
        let cancelled_calls = AtomicUsize::new(0);
        assert_eq!(
            run_h3_candidates(&endpoints, stop.clone(), |_| {
                cancelled_calls.fetch_add(1, Ordering::Relaxed);
                stop.cancel();
                std::future::pending()
            })
            .await,
            NetworkProbeResult::Cancelled
        );
        assert_eq!(cancelled_calls.load(Ordering::Relaxed), 1);
    }
}
