//! In-memory regressions for WARP bootstrap and pooled DoT recovery.
use super::*;

impl FinalHarness {
    fn resolver_with_dialer(
        &self,
        dialer: Arc<dyn crate::tcp::TcpDialer>,
        bootstrap: Option<crate::dns::Resolver>,
    ) -> FinalDohResolver {
        FinalDohResolver {
            inner: EncryptedResolver::new(
                self.resolver.inner.settings.clone(),
                self.protector.clone(),
                self.quality.clone(),
                &self.cancel,
                (*self.resolver.inner.tls).clone(),
                DnsConnector::Final {
                    dialer,
                    budget: self.budget.clone(),
                    bootstrap,
                },
            ),
        }
    }
}

struct FamilyDialer {
    inner: Arc<FinalTestDialer>,
    first_ipv4: bool,
    silent: bool,
    attempted: StdMutex<Vec<IpAddr>>,
}

#[async_trait]
impl crate::tcp::TcpDialer for FamilyDialer {
    async fn connect(
        &self,
        target: crate::tcp::TcpTarget,
        deadline: Instant,
        cancel: &CancellationToken,
        class: crate::tcp::FlowClass,
    ) -> Result<crate::tcp::TcpStream, crate::tcp::DialError> {
        assert_eq!(class, crate::tcp::FlowClass::Dns);
        let endpoint = target.socket_address().unwrap();
        if endpoint.port() != 53 {
            self.attempted.lock().unwrap().push(endpoint.ip());
            if endpoint.is_ipv4() == self.first_ipv4 {
                if self.silent {
                    pending::<()>().await;
                }
                return Err(crate::tcp::DialError::Refused);
            }
            return self.inner.connect(target, deadline, cancel, class).await;
        }
        assert_eq!(endpoint, "192.0.2.53:53".parse().unwrap());
        let (client, mut peer) = tokio::io::duplex(4096);
        let stop = cancel.clone();
        let first_ipv4 = self.first_ipv4;
        tokio::spawn(async move {
            let serve = async {
                while let Ok(length) = peer.read_u16().await {
                    let mut query = vec![0; length as usize];
                    if peer.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    assert_eq!(&query[12..query.len() - 4], b"\x08resolver\x04test\x00");
                    // The family returned first has an unreachable encrypted peer.
                    if (query[query.len() - 3] == 28) == first_ipv4 {
                        sleep(Duration::from_millis(20)).await;
                    }
                    let response = test_response(&query, Behavior::Echo);
                    if peer.write_u16(response.len() as u16).await.is_err()
                        || peer.write_all(&response).await.is_err()
                    {
                        break;
                    }
                }
            };
            tokio::select! { _ = stop.cancelled() => {}, _ = serve => {} }
        });
        let active = self.inner.leases.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.inner.leases.peak.fetch_max(active, Ordering::AcqRel);
        Ok(Box::new(FinalTestStream(client, self.inner.leases.clone())))
    }
}

#[tokio::test]
async fn empty_bootstrap_keeps_reachable_second_family_for_doh_and_dot() {
    for mode in [ConfigMode::Doh, ConfigMode::Dot] {
        for first_ipv4 in [true, false] {
            for silent in [false, true] {
                let harness = FinalHarness::for_endpoints(
                    mode,
                    Behavior::Echo,
                    Behavior::Echo,
                    true,
                    vec![],
                    None,
                );
                let dialer = Arc::new(FamilyDialer {
                    inner: harness.dialer.clone(),
                    first_ipv4,
                    silent,
                    attempted: StdMutex::default(),
                });
                let dns = Arc::new(crate::dns_stream::StreamDns::new(
                    dialer.clone(),
                    harness.protector.clone(),
                    harness.cancel.clone(),
                    Arc::default(),
                ));
                let bootstrap = crate::dns::Resolver::for_streams(
                    dns.clone(),
                    vec!["192.0.2.53".parse().unwrap()],
                    usque_core::ProxyDnsMode::Remote,
                    harness.protector.clone(),
                );
                let resolver = harness.resolver_with_dialer(dialer.clone(), Some(bootstrap));
                let query = test_query(600);
                let result = resolver.query(&query, Instant::now() + QUERY_TIMEOUT).await;
                let attempted = dialer.attempted.lock().unwrap().clone();
                harness.cancel.cancel();
                resolver.inner.clear_idle_pool(true);
                dns.clear();
                harness.stop().await;
                assert_eq!(
                    result.unwrap().as_ref(),
                    test_response(&query, Behavior::Echo),
                    "mode={mode:?}, first_ipv4={first_ipv4}, silent={silent}"
                );
                assert_eq!(attempted.len(), 2);
                assert_eq!(attempted[0].is_ipv4(), first_ipv4);
                assert_ne!(attempted[1].is_ipv4(), first_ipv4);
            }
        }
    }
}

struct RetiringDotDialer {
    inner: Arc<FinalTestDialer>,
    close_idle: bool,
    followup: Behavior,
}

#[async_trait]
impl crate::tcp::TcpDialer for RetiringDotDialer {
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
    fn session_generation(&self) -> Option<u64> {
        self.inner.session_generation()
    }
    async fn connect(
        &self,
        target: crate::tcp::TcpTarget,
        _: Instant,
        cancel: &CancellationToken,
        class: crate::tcp::FlowClass,
    ) -> Result<crate::tcp::TcpStream, crate::tcp::DialError> {
        assert_eq!(class, crate::tcp::FlowClass::Dns);
        assert_eq!(
            target.socket_address(),
            Some(SocketAddr::new("1.1.1.1".parse().unwrap(), self.inner.port))
        );
        let first = {
            let mut targets = self.inner.targets.lock().unwrap();
            targets.push(target);
            targets.len() == 1
        };
        let (client, peer) = tokio::io::duplex(4096);
        let config = self.inner.server.clone();
        let counts = self.inner.queries.clone();
        let stop = cancel.clone();
        let close_idle = self.close_idle;
        let followup = self.followup;
        tokio::spawn(async move {
            let serve = async {
                let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config).accept(peer).await else {
                    return;
                };
                if first {
                    let length = tls.read_u16().await.unwrap();
                    let mut query = vec![0; length as usize];
                    tls.read_exact(&mut query).await.unwrap();
                    let response = test_response(&query, Behavior::Echo);
                    tls.write_u16(response.len() as u16).await.unwrap();
                    tls.write_all(&response).await.unwrap();
                    tls.flush().await.unwrap();
                    if close_idle {
                        tls.shutdown().await.unwrap();
                        return;
                    }
                }
                serve_dot(tls, followup, counts).await;
            };
            tokio::select! { _ = stop.cancelled() => {}, _ = serve => {} }
        });
        let active = self.inner.leases.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.inner.leases.peak.fetch_max(active, Ordering::AcqRel);
        Ok(Box::new(FinalTestStream(client, self.inner.leases.clone())))
    }
}

fn retiring_dot(close_idle: bool, followup: Behavior) -> (FinalHarness, FinalDohResolver) {
    let harness = FinalHarness::for_endpoints(
        ConfigMode::Dot,
        Behavior::Echo,
        Behavior::Echo,
        true,
        vec!["1.1.1.1".parse().unwrap()],
        None,
    );
    let resolver = harness.resolver_with_dialer(
        Arc::new(RetiringDotDialer {
            inner: harness.dialer.clone(),
            close_idle,
            followup,
        }),
        None,
    );
    (harness, resolver)
}

#[tokio::test]
async fn single_dot_endpoint_reopens_server_closed_pooled_connection() {
    let (harness, resolver) = retiring_dot(true, Behavior::Echo);
    for id in 602..605 {
        let query = test_query(id);
        assert_eq!(
            resolver
                .query(&query, Instant::now() + QUERY_TIMEOUT)
                .await
                .unwrap()
                .as_ref(),
            test_response(&query, Behavior::Echo)
        );
    }
    assert_eq!(harness.dialer.targets.lock().unwrap().len(), 2);
    harness.cancel.cancel();
    resolver.inner.clear_idle_pool(true);
    harness.stop().await;
}

#[tokio::test]
async fn dot_reconnect_is_bounded_and_invalid_reused_responses_are_terminal() {
    for (close_idle, followup, expected) in [
        (true, Behavior::Eof, DirectDnsError::QueryFailed),
        (true, Behavior::BadId, DirectDnsError::InvalidResponse),
        (false, Behavior::BadId, DirectDnsError::InvalidResponse),
        (false, Behavior::ZeroLength, DirectDnsError::InvalidResponse),
        (
            false,
            Behavior::Delay(Duration::from_secs(10)),
            DirectDnsError::Timeout,
        ),
    ] {
        let (harness, resolver) = retiring_dot(close_idle, followup);
        resolver
            .query(&test_query(605), Instant::now() + QUERY_TIMEOUT)
            .await
            .unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(500);
        let result = resolver.query(&test_query(606), deadline).await;
        assert_eq!(result, Err(expected));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            harness.dialer.targets.lock().unwrap().len(),
            if close_idle { 2 } else { 1 }
        );
        harness.cancel.cancel();
        resolver.inner.clear_idle_pool(true);
        harness.stop().await;
    }
}

#[tokio::test]
async fn dot_reconnect_preserves_deadline_cancellation_and_network_epochs() {
    for change in 0..4 {
        let (harness, resolver) = retiring_dot(true, Behavior::Delay(Duration::from_secs(10)));
        resolver
            .query(&test_query(607), Instant::now() + QUERY_TIMEOUT)
            .await
            .unwrap();
        let query = test_query(608);
        let started = Instant::now();
        let operation = resolver.query(&query, started + Duration::from_millis(500));
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => panic!("query completed before reconnect: {result:?}"),
            _ = async {
                while harness.dialer.targets.lock().unwrap().len() < 2 {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
        let expected = match change {
            0 => DirectDnsError::Timeout,
            1 => {
                harness.cancel.cancel();
                DirectDnsError::Cancelled
            }
            2 => {
                harness.protector.generation.store(8, Ordering::Release);
                DirectDnsError::NetworkChanged
            }
            _ => {
                harness.dialer.generation.store(2, Ordering::Release);
                DirectDnsError::NetworkChanged
            }
        };
        assert_eq!(operation.await, Err(expected));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(harness.dialer.targets.lock().unwrap().len(), 2);
        harness.cancel.cancel();
        resolver.inner.clear_idle_pool(true);
        harness.stop().await;
    }
}
