//! Interoperability with an independent rustls server and real two-party MPC.
use std::{
    io::{Read, Write},
    sync::Arc,
    time::Duration,
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
use tokenhive_tls13::{Policy, hub_handshake, provider_handshake};
use tokio::io::AsyncReadExt;

async fn run_case(capacity: usize, wrong_name: bool, mismatch: bool, invalid_credential: bool) {
    let mut crypto = rustls::crypto::ring::default_provider();
    crypto
        .cipher_suites
        .retain(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls_pki_types::CertificateDer::from(
                SERVER_CERT_DER.to_vec(),
            )],
            rustls_pki_types::PrivateKeyDer::try_from(SERVER_KEY_DER.to_vec()).unwrap(),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = vec![b'x'; capacity - 512];
    let expected_body = body.clone();
    let (client_done, server_hold) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            sock,
        );
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            match tls.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    assert!(
                        !wrong_name && !mismatch && !invalid_credential,
                        "rejected session delivered application bytes"
                    );
                    received.extend_from_slice(&buffer[..n]);
                }
                result if wrong_name || mismatch || invalid_credential => {
                    assert!(received.is_empty());
                    assert!(
                        !matches!(result,Err(ref e) if matches!(e.kind(),std::io::ErrorKind::TimedOut|std::io::ErrorKind::WouldBlock)),
                        "failure leaked a live upstream connection"
                    );
                    return;
                }
                result => panic!("unexpected server read: {result:?}"),
            }
            if let Some(split) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&received[..split]).unwrap();
                let len = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if received.len() == split + 4 + len {
                    assert_eq!(&received[split + 4..], expected_body);
                    break;
                }
            }
        }
        assert!(
            String::from_utf8_lossy(&received).contains("Authorization: Bearer secret-fixture")
        );
        // Exercise a server-initiated update as well as the client's credential/body boundary.
        tls.conn.refresh_traffic_keys().unwrap();
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
        tls.flush().unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();
        // Keep TCP alive until Hub consumes close_notify. Dropping a socket
        // with an unread KeyUpdate reply can send RST and discard response
        // records that are already in flight.
        let _ = server_hold.recv_timeout(Duration::from_secs(30));
    });
    let upstream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (a, b) = tokio::io::duplex(1 << 20);
    let (output, mut response) = tokio::io::duplex(1 << 20);
    let policy = Policy {
        server_name: if wrong_name {
            "wrong.example"
        } else {
            SERVER_DOMAIN
        }
        .into(),
        max_request: capacity,
        max_response: 1 << 20,
    };
    let roots = tlsn_core::webpki::RootCertStore {
        roots: vec![tlsn_core::webpki::CertificateDer(CA_CERT_DER.to_vec())],
    };
    let start = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            hub_handshake(a, output, roots, policy.clone()),
            provider_handshake(b, upstream, policy)
        )
    })
    .await
    .expect("handshake timeout");
    if wrong_name {
        assert!(result.is_err());
        server.join().unwrap();
        return;
    }
    let (mut hub, mut provider) = result.unwrap();
    let warm = start.elapsed();
    let mut request =
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: test-server.io\r\nAuthorization: Bearer "
            .to_vec();
    let begin = request.len();
    request.extend_from_slice(&[0; 14]);
    let end = request.len();
    request.extend_from_slice(format!("\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
    request.extend_from_slice(&body);
    let mut peer_request = request.clone();
    if mismatch {
        *peer_request.last_mut().unwrap() ^= 1;
    }
    let mut credential = b"secret-fixture".to_vec();
    if invalid_credential {
        credential[0] = b'\r';
    }
    let online = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(
            hub.request(&request, begin..end),
            provider.request(&peer_request, begin..end, &credential)
        )
    })
    .await
    .expect("request timeout");
    if mismatch || invalid_credential {
        assert!(result.is_err());
        drop(hub);
        drop(provider);
        server.join().unwrap();
        return;
    }
    result.unwrap();
    eprintln!(
        "TLS13 capacity={capacity} warm={warm:?} online={:?}",
        online.elapsed()
    );
    tokio::time::timeout(Duration::from_secs(30), hub.response())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    response.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.ends_with(b"ok"));
    client_done.send(()).unwrap();
    server.join().unwrap();
    assert!(hub.request(&request, begin..end).await.is_err());
    assert!(
        provider
            .request(&request, begin..end, b"secret-fixture")
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real two-party MPC interoperability and capacity matrix"]
async fn real_keyupdate_request() {
    for capacity in [4096, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 5 << 20] {
        run_case(capacity, false, false, false).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real two-party MPC rejection paths"]
async fn wrong_dns_and_mismatched_plan_deliver_no_application_data() {
    run_case(4096, true, false, false).await;
    run_case(4096, false, true, false).await;
    run_case(4096, false, false, true).await;
}
