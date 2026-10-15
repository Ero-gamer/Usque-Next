use super::*;
use crate::diagnostic_probe::{
    H3ProbeOutcome, H3ProbeTerminal, NetworkProbeResult as ResultCode, PROBE_IO_TIMEOUT, elapsed_ms,
};

pub(crate) async fn handshake(
    endpoint: SocketAddr,
    sni: &str,
    identity: &MasqueTlsIdentity,
    protector: Arc<dyn SocketProtector>,
    cancellation: CancellationToken,
) -> H3ProbeOutcome {
    let started = Instant::now();
    let generation = protector.network_generation().unwrap_or_default();
    let operation = async {
        let prepared = prepare_udp_for_generation(endpoint, generation, protector.as_ref())
            .await
            .map_err(|error| match error {
                SocketPrepareError::StaleGeneration => ResultCode::NetworkChanged.into(),
                SocketPrepareError::Protection(_) => {
                    H3ProbeOutcome::Terminal(H3ProbeTerminal::Protection)
                }
                SocketPrepareError::Io(_) => ResultCode::Failed.into(),
            })?;
        let (mut config, pin) = quic_config(identity, INITIAL_SAFE_UDP_PAYLOAD)
            .map_err(|_| H3ProbeOutcome::Terminal(H3ProbeTerminal::Identity))?;
        config.discover_pmtu(false);
        config.set_disable_active_migration(true);
        config.set_initial_max_data(0);
        config.set_initial_max_streams_bidi(0);
        config.set_initial_max_streams_uni(0);
        let mut scid = [0u8; CONNECTION_ID_LENGTH];
        boring::rand::rand_bytes(&mut scid)
            .map_err(|_| H3ProbeOutcome::Terminal(H3ProbeTerminal::Identity))?;
        let mut connection = quiche::connect_with_buffer_factory::<H3BufferFactory>(
            Some(sni),
            &quiche::ConnectionId::from_ref(&scid),
            prepared.local_addr,
            endpoint,
            &mut config,
        )
        .map_err(|_| H3ProbeOutcome::Terminal(H3ProbeTerminal::Identity))?;
        let mut incoming = vec![0u8; 65_536];
        let mut outgoing = [0u8; INITIAL_SAFE_UDP_PAYLOAD];
        loop {
            if protector.network_generation().unwrap_or_default() != generation
                || prepared.egress_lease.generation() != Some(generation)
            {
                return Err(ResultCode::NetworkChanged.into());
            }
            if pin.rejected() || connection.is_closed() || connection.is_draining() {
                return Err(connection_failure(&connection, &pin));
            }
            // Bound each drain, honor pacing, and never construct an HTTP/3
            // object: only QUIC handshake/control datagrams can exist here.
            for _ in 0..16 {
                let (length, info) = match connection.send(&mut outgoing) {
                    Ok(value) => value,
                    Err(quiche::Error::Done) => break,
                    Err(_) => return Err(connection_failure(&connection, &pin)),
                };
                if info.to != endpoint || info.from != prepared.local_addr {
                    return Err(H3ProbeOutcome::Terminal(H3ProbeTerminal::Protection));
                }
                sleep_until(Instant::from_std(info.at)).await;
                if protector.network_generation().unwrap_or_default() != generation {
                    return Err(ResultCode::NetworkChanged.into());
                }
                let sent = prepared
                    .socket
                    .send_to(&outgoing[..length], endpoint)
                    .await
                    .map_err(|_| H3ProbeOutcome::from(ResultCode::Failed))?;
                if sent != length {
                    return Err(ResultCode::Failed.into());
                }
            }
            if connection.is_established() {
                // Flush the client's Finished before reporting a successful
                // bidirectional handshake. There are still no HTTP streams.
                return Ok(ResultCode::Passed {
                    milliseconds: elapsed_ms(started),
                });
            }
            let wakeup = connection
                .timeout()
                .unwrap_or(Duration::from_millis(100))
                .min(Duration::from_millis(100));
            tokio::select! {
                packet = prepared.socket.recv_from(&mut incoming) => {
                    let (length, from) = packet.map_err(|_| H3ProbeOutcome::from(ResultCode::Failed))?;
                    if from != endpoint { continue; }
                    if protector.network_generation().unwrap_or_default() != generation { return Err(ResultCode::NetworkChanged.into()); }
                    match connection.recv(&mut incoming[..length], quiche::RecvInfo { from, to: prepared.local_addr }) {
                        Ok(_) | Err(quiche::Error::Done) => {},
                        Err(_) => return Err(connection_failure(&connection, &pin)),
                    }
                }
                _ = tokio::time::sleep(wakeup) => connection.on_timeout(),
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => ResultCode::Cancelled.into(),
        result = timeout(PROBE_IO_TIMEOUT, operation) => match result {
            Ok(Ok(result)) => result.into(),
            Ok(Err(outcome)) => outcome,
            Err(_) => ResultCode::TimedOut.into(),
        },
    }
}

fn connection_failure(connection: &H3QuicConnection, pin: &PinState) -> H3ProbeOutcome {
    if pin.rejected() {
        H3ProbeOutcome::Terminal(H3ProbeTerminal::PinMismatch)
    } else if connection
        .peer_error()
        .is_some_and(|error| !error.is_app && (0x100..=0x1ff).contains(&error.error_code))
    {
        // A peer TLS alert may reject the enrolled client identity. It cannot
        // be converted into a successful diagnosis by trying another address.
        H3ProbeOutcome::Terminal(H3ProbeTerminal::Identity)
    } else {
        ResultCode::Failed.into()
    }
}
