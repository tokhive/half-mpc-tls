use std::{future::IntoFuture, time::Duration};

use tls_server_fixture::SERVER_DOMAIN;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_SENT_RECORDS: usize = 4;
const MAX_RECV_DATA: usize = 1 << 14;
const MAX_RECV_RECORDS: usize = 6;

/// Exercises the actual two-party MPC stack and a real TLS 1.2 fixture.
///
/// This is ignored in the default suite because MPC preprocessing is expensive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "expensive two-party MPC integration test"]
async fn releases_server_keys_after_upstream_authentication_before_tls_close() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("tlsn=info,mpc_tls=info")
        .try_init();

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut prover_session = Session::new(prover_socket.compat());
    let mut verifier_session = Session::new(verifier_socket.compat());

    let prover = prover_session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = verifier_session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(test_root_store())
                .build()
                .unwrap(),
        )
        .unwrap();

    let (prover_driver, prover_handle) = prover_session.split();
    let (verifier_driver, verifier_handle) = verifier_session.split();
    tokio::spawn(prover_driver);
    tokio::spawn(verifier_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let verifier_commit = async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("prover requested an unexpected protocol")
        };
        verifier.accept().await.unwrap()
    };
    let (prover, mut verifier) = tokio::join!(prover.commit(config), verifier_commit);
    let prover = prover.unwrap();

    let expected_server = ServerName::Dns(SERVER_DOMAIN.try_into().unwrap());
    let authentication = verifier
        .authenticate_upstream(expected_server.clone())
        .unwrap();

    let (tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(expected_server)
                .root_store(test_root_store())
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .unwrap();

    // Match the production one-shot schedule: client AES is already evaluated
    // when authentication decides whether server keys may be released.
    prover.control().selective().unwrap().require_selective();
    verifier.selective_control().require_selective();
    let prover_task = tokio::spawn(prover.into_future());
    let verifier_task = tokio::spawn(verifier.run());

    // The prover future must drive connection-pool handshake warmup without
    // emitting any application data to the upstream server.
    let mut release = tokio::time::timeout(Duration::from_secs(60), authentication.wait())
        .await
        .expect("upstream authentication timed out")
        .expect("upstream authentication failed");

    assert_eq!(release.server_name().to_string(), SERVER_DOMAIN);
    let keys = release
        .try_take()
        .expect("server-key decode failed")
        .expect("server keys were not decoded at the authenticated handshake boundary");
    assert_ne!(keys.write_key(), &[0; 16]);
    assert_ne!(keys.fixed_iv(), &[0; 4]);

    // This fixture proves release at the authenticated handshake boundary.
    // The sidecar integration test separately exercises selective application
    // traffic and clean response delivery. Abort here so this test does not
    // enter the non-selective finalization path after its assertion is done.
    drop(tls_connection);
    prover_task.abort();
    verifier_task.abort();
    server_task.abort();
    prover_handle.close();
    verifier_handle.close();
}

/// Proves that a valid chain for a different DNS identity cannot authorize release.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "expensive two-party MPC integration test"]
async fn rejects_wrong_upstream_dns_identity_without_releasing_keys() {
    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut prover_session = Session::new(prover_socket.compat());
    let mut verifier_session = Session::new(verifier_socket.compat());
    let prover = prover_session
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = verifier_session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(test_root_store())
                .build()
                .unwrap(),
        )
        .unwrap();

    let (prover_driver, prover_handle) = prover_session.split();
    let (verifier_driver, verifier_handle) = verifier_session.split();
    tokio::spawn(prover_driver);
    tokio::spawn(verifier_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));
    let verifier_commit = async {
        let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap() else {
            panic!("prover requested an unexpected protocol")
        };
        verifier.accept().await.unwrap()
    };
    let (prover, mut verifier) = tokio::join!(prover.commit(config), verifier_commit);
    let prover = prover.unwrap();

    let authentication = verifier
        .authenticate_upstream(ServerName::Dns("wrong.test-server.io".try_into().unwrap()))
        .unwrap();
    let (tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(test_root_store())
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .unwrap();

    // Match the production one-shot schedule: client AES is already evaluated
    // when authentication decides whether server keys may be released.
    prover.control().selective().unwrap().require_selective();
    verifier.selective_control().require_selective();
    let prover_task = tokio::spawn(prover.into_future());
    let verifier_task = tokio::spawn(verifier.run());
    let authentication = tokio::time::timeout(Duration::from_secs(60), authentication.wait())
        .await
        .expect("upstream authentication timed out");
    let error = match authentication {
        Err(error) => error,
        Ok(_) => panic!("wrong DNS identity authorized server-key release"),
    };
    assert!(!error.to_string().contains("connection ended before"));

    drop(tls_connection);
    prover_task.abort();
    verifier_task.abort();
    server_task.abort();
    prover_handle.close();
    verifier_handle.close();
}

fn test_root_store() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}
