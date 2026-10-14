use super::*;
use proptest::prelude::*;

// Deterministic Brotli fixtures generated once with Node's zlib.brotliCompressSync.
// Tests decode embedded bytes and need no compressor or external process.
const PLAIN: &[u8] = b"bounded certificate fixture";
const COMPRESSED: &[u8] = &[
    27, 26, 0, 248, 165, 203, 228, 232, 234, 100, 33, 162, 0, 147, 174, 200, 227, 146, 124, 87,
    175, 190, 22,
];
const AT_LIMIT: &[u8] = &[91, 255, 255, 143, 95, 34, 44, 30, 11, 4, 114, 239, 31, 0];
const OVER_LIMIT: &[u8] = &[155, 0, 0, 16, 248, 37, 194, 226, 177, 64, 64, 247, 254, 1];
const LARGE_WINDOW: &[u8] = &[
    17, 94, 104, 0, 224, 151, 46, 147, 163, 171, 147, 133, 136, 2, 76, 186, 66, 30, 46, 145, 239,
    234, 213, 215, 2,
];
const NONFINAL_WINDOW24: &[u8] = &[
    15, 13, 0, 248, 165, 203, 228, 232, 234, 100, 33, 162, 0, 147, 174, 200, 227, 146, 124, 87,
    175, 190, 22, 3, 3,
];

#[test]
fn certificate_decoder_accepts_valid_bounded_data() {
    let mut output = Vec::new();
    BrotliDecoder.decompress(COMPRESSED, &mut output).unwrap();
    assert_eq!(output, PLAIN);
}

#[test]
fn certificate_decoder_accepts_exact_one_mib_limit() {
    let mut output = Vec::new();
    BrotliDecoder.decompress(AT_LIMIT, &mut output).unwrap();
    assert_eq!(output.len(), 1024 * 1024);
    assert!(output.iter().all(|byte| *byte == b'a'));
}

#[test]
fn certificate_decoder_rejects_expansion_above_limit_without_partial_output() {
    let mut output = Vec::new();
    assert!(BrotliDecoder.decompress(OVER_LIMIT, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn certificate_decoder_rejects_every_truncated_prefix_without_partial_output() {
    for length in 0..COMPRESSED.len() {
        let mut output = Vec::new();
        assert!(
            BrotliDecoder
                .decompress(&COMPRESSED[..length], &mut output)
                .is_err(),
            "accepted truncated prefix of {length} bytes"
        );
        assert!(output.is_empty());
    }
}

#[test]
fn certificate_decoder_rejects_invalid_stream_without_partial_output() {
    let mut output = Vec::new();
    assert!(BrotliDecoder.decompress(&[0xff; 32], &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn certificate_decoder_propagates_output_failure() {
    struct RejectWrite;
    impl Write for RejectWrite {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        BrotliDecoder
            .decompress(COMPRESSED, &mut RejectWrite)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WriteZero
    );
}

#[test]
fn certificate_decoder_rejects_nonstandard_large_window() {
    let mut output = Vec::new();
    assert!(BrotliDecoder.decompress(LARGE_WINDOW, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn certificate_decoder_rejects_excessive_ring_allocation_without_panicking() {
    // Valid standard Brotli with a non-final 24-bit-window block. Only 27
    // bytes would be emitted, but it requests a 16 MiB working ring first.
    let mut output = Vec::new();
    assert!(
        BrotliDecoder
            .decompress(NONFINAL_WINDOW24, &mut output)
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn certificate_decoder_accepts_large_advertised_window_with_small_actual_ring() {
    let mut compressed = COMPRESSED.to_vec();
    compressed[0] = 31; // Standard 24-bit window with a small final metablock.
    let mut output = Vec::new();
    BrotliDecoder.decompress(&compressed, &mut output).unwrap();
    assert_eq!(output, PLAIN);
}

#[test]
fn certificate_decoder_rejects_trailing_data() {
    let mut compressed = COMPRESSED.to_vec();
    compressed.extend_from_slice(&[0, 1, 2]);
    let mut output = Vec::new();
    assert!(BrotliDecoder.decompress(&compressed, &mut output).is_err());
    assert!(output.is_empty());
}

#[test]
fn certificate_decoder_rejects_excessive_compressed_input() {
    let mut output = Vec::new();
    assert!(
        BrotliDecoder
            .decompress(&vec![0; 1024 * 1024 + 1], &mut output)
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn certificate_byte_allocator_releases_budget_and_rejects_overflow() {
    use brotli_decompressor::{Allocator, SliceWrapper};

    let mut allocator = BrotliByteAllocator::default();
    let allocation = allocator.alloc_cell(4 * 1024 * 1024);
    assert_eq!(allocation.slice().len(), 4 * 1024 * 1024);
    assert!(allocator.alloc_cell(128 * 1024).slice().is_empty());
    assert!(allocator.alloc_cell(usize::MAX).slice().is_empty());
    allocator.free_cell(allocation);
    assert_eq!(allocator.allocated, 0);
    let replacement = allocator.alloc_cell(4 * 1024 * 1024);
    assert_eq!(replacement.slice().len(), 4 * 1024 * 1024);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_compressed_certificates_never_panic_or_emit_unbounded_output(
        input in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut output = Vec::new();
        let result = BrotliDecoder.decompress(&input, &mut output);
        prop_assert!(output.len() <= 1024 * 1024);
        if result.is_err() {
            prop_assert!(output.is_empty());
        }
    }

    #[test]
    fn mutated_or_truncated_certificate_streams_remain_bounded(
        fixture_index in 0usize..5,
        mutations in prop::collection::vec((any::<usize>(), any::<u8>()), 0..5),
        truncate in any::<bool>(),
        length in any::<usize>(),
    ) {
        let fixtures = [COMPRESSED, AT_LIMIT, OVER_LIMIT, LARGE_WINDOW, NONFINAL_WINDOW24];
        let mut input = fixtures[fixture_index].to_vec();
        for (index, mask) in mutations {
            let index = index % input.len();
            input[index] ^= mask;
        }
        if truncate {
            input.truncate(length % (input.len() + 1));
        }
        let mut output = Vec::new();
        let result = BrotliDecoder.decompress(&input, &mut output);
        prop_assert!(output.len() <= 1024 * 1024);
        if result.is_err() {
            prop_assert!(output.is_empty());
        }
    }
}

fn identity(
    local: &usque_core::MasqueKeyPair,
    peer: &usque_core::MasqueKeyPair,
) -> crate::h2::MasqueTlsIdentity {
    crate::h2::MasqueTlsIdentity::new(
        local.private_sec1_der().unwrap(),
        &peer.public_spki_der().unwrap(),
        "192.0.2.2".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    )
    .unwrap()
    .with_fingerprint(TlsFingerprint::Chrome131)
}

async fn h2_authentication_case(correct_pin: bool) {
    use boring::ssl::{SslAcceptor, SslMethod};
    use tokio::time::{Duration, timeout};

    let client_key = usque_core::MasqueKeyPair::generate();
    let server_key = usque_core::MasqueKeyPair::generate();
    let wrong_key = usque_core::MasqueKeyPair::generate();
    let client_identity = identity(
        &client_key,
        if correct_pin { &server_key } else { &wrong_key },
    );
    let server_identity = identity(&server_key, &client_key);
    let connector = crate::h2::fingerprint_test_connector(&client_identity).unwrap();
    let mut client_config = connector.configure().unwrap();
    configure_h2_connection(&mut client_config, TlsFingerprint::Chrome131).unwrap();

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    crate::h2::configure_client_identity_and_pin(&mut acceptor, &server_identity).unwrap();
    let acceptor = acceptor.build();
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let (client, server) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            tokio_boring::connect(client_config, "example.com", client_io),
            tokio_boring::accept(&acceptor, server_io)
        )
    })
    .await
    .expect("in-memory TLS authentication must terminate");
    if correct_pin {
        let client = client.expect("the pinned peer must be accepted");
        let server = server.expect("the client identity must remain usable");
        assert_eq!(client.ssl().version_str(), "TLSv1.3");
        let client_certificate = server.ssl().peer_certificate().expect("client certificate");
        assert_eq!(
            client_certificate
                .public_key()
                .unwrap()
                .public_key_to_der()
                .unwrap(),
            client_key.public_spki_der().unwrap()
        );
    } else {
        assert!(client.is_err(), "Chrome must not bypass the endpoint pin");
        assert!(server.is_err());
    }
}

#[tokio::test]
async fn chrome_h2_accepts_pinned_peer_and_sends_client_identity() {
    h2_authentication_case(true).await;
}

#[tokio::test]
async fn chrome_h2_rejects_wrong_endpoint_pin() {
    h2_authentication_case(false).await;
}

fn transfer_quic_packets(
    sender: &mut quiche::Connection,
    receiver: &mut quiche::Connection,
) -> Result<(), quiche::Error> {
    let mut wire = [0; 1500];
    // The handshake is deliberately bounded and uses memory only. No socket,
    // timer, TUN, registration or real endpoint is involved.
    for _ in 0..32 {
        let (length, info) = match sender.send(&mut wire) {
            Ok(packet) => packet,
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(error),
        };
        receiver.recv(
            &mut wire[..length],
            quiche::RecvInfo {
                from: info.from,
                to: info.to,
            },
        )?;
    }
    panic!("QUIC peer exceeded the bounded handshake packet budget");
}

fn h3_authentication_case(correct_pin: bool) {
    use boring::ssl::SslMethod;

    let client_key = usque_core::MasqueKeyPair::generate();
    let server_key = usque_core::MasqueKeyPair::generate();
    let wrong_key = usque_core::MasqueKeyPair::generate();
    let client_identity = identity(
        &client_key,
        if correct_pin { &server_key } else { &wrong_key },
    );
    let server_identity = identity(&server_key, &client_key);
    let (mut client_config, client_pin) = crate::h3::quic_config(&client_identity, 1350).unwrap();
    let mut server_tls = SslContextBuilder::new(SslMethod::tls()).unwrap();
    let server_pin =
        crate::h2::configure_client_identity_and_pin(&mut server_tls, &server_identity).unwrap();
    let mut server_config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, server_tls).unwrap();
    server_config.set_application_protos(&[b"h3"]).unwrap();
    let client_address = "127.0.0.1:12000".parse().unwrap();
    let server_address = "127.0.0.1:12001".parse().unwrap();
    let client_id = quiche::ConnectionId::from_ref(&[0x11; 20]);
    let mut client = quiche::connect(
        Some("example.com"),
        &client_id,
        client_address,
        server_address,
        &mut client_config,
    )
    .unwrap();
    let mut wire = [0; 1500];
    let (initial_length, _) = client.send(&mut wire).unwrap();
    let header = quiche::Header::from_slice(&mut wire[..initial_length], 20).unwrap();
    let mut server = quiche::accept(
        &header.dcid,
        None,
        server_address,
        client_address,
        &mut server_config,
    )
    .unwrap();
    server
        .recv(
            &mut wire[..initial_length],
            quiche::RecvInfo {
                from: client_address,
                to: server_address,
            },
        )
        .unwrap();
    let mut handshake_error = None;
    for _ in 0..32 {
        let exchange = transfer_quic_packets(&mut client, &mut server)
            .and_then(|()| transfer_quic_packets(&mut server, &mut client));
        if let Err(error) = exchange {
            handshake_error = Some(error);
            break;
        }
        if client.is_established() && server.is_established() {
            break;
        }
    }
    if correct_pin {
        assert!(handshake_error.is_none(), "{handshake_error:?}");
        assert!(client.is_established() && server.is_established());
        assert!(!client_pin.rejected() && !server_pin.rejected());
        assert_eq!(client.application_proto(), b"h3");
        let certificate = boring::x509::X509::from_der(
            server
                .peer_cert()
                .expect("QUIC client certificate must be sent"),
        )
        .unwrap();
        assert_eq!(
            certificate
                .public_key()
                .unwrap()
                .public_key_to_der()
                .unwrap(),
            client_key.public_spki_der().unwrap()
        );
    } else {
        assert!(handshake_error.is_some());
        assert!(
            client_pin.rejected(),
            "the enrolled pin must reject the peer"
        );
        assert!(!client.is_established() && !server.is_established());
    }
}

#[test]
fn chrome_h3_accepts_pinned_peer_and_sends_client_identity() {
    h3_authentication_case(true);
}

#[test]
fn chrome_h3_rejects_wrong_endpoint_pin() {
    h3_authentication_case(false);
}
