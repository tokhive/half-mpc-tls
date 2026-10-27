//! Unix socket service and lifecycle enforcement for TokenHive sidecars.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod canonical;
mod credential;
mod response;
mod tls13;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::{Future, IntoFuture},
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{AsyncWriteExt as FuturesAsyncWriteExt, task::AtomicWaker};
use mpc_tls::{SelectiveFollowerControl, SelectiveLeaderControl};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tlsn::{
    Session as TlsnSession,
    config::{
        prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig,
        verifier::VerifierConfig,
    },
    connection::ServerName,
    prover::TlsConnection,
    verifier::VerifierCommitStart,
    webpki::RootCertStore,
};
use tokenhive_sidecar_protocol::{
    Capabilities, DeliveryAck, FrameReader, FrameType, FrameWriter, MpcCapacity, Operation, Role,
    RpcCommand, RpcError, RpcResult, StreamInput, accept_hello, read_command, read_stream,
    write_result,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{UnixListener, UnixStream},
    task::JoinSet,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use zeroize::Zeroizing;

use canonical::{SelectiveRequestParams, validate_request};
use credential::EmptyCredentialResolver;
use response::pump_authenticated_response;

pub use credential::{
    CredentialResolver, CredentialStoreError, FileCredentialResolver,
    ReloadingFileCredentialResolver,
};

const MAX_CREDENTIAL_ID_SIZE: usize = 128;
const ATTACHMENT_BUFFER_SIZE: usize = 1 << 20;
const ATTACHMENT_TOKEN_SIZE: usize = 32;
// Selective request MPC remains tightly bounded; authenticated server records
// are forwarded blind and decrypted locally by Hub up to the response limit.
// A 5 MiB tier performs its AES/GHASH preprocessing before the session enters
// the ready pool. Keep this outside request latency, but allow enough time for
// the bounded batches to finish on modest Provider hardware.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const REQUEST_DELIVERY_TIMEOUT: Duration = Duration::from_secs(120);
const TLS12_AES_GCM_RECORD_OVERHEAD: u64 = 5 + 8 + 16;
const TLS_PLAINTEXT_FRAGMENT_SIZE: usize = 16 << 10;

#[derive(Debug, Clone)]
struct MpcLimits {
    max_sent_data: usize,
    max_sent_records: usize,
    max_recv_data: usize,
    max_recv_records_online: usize,
}

impl Default for MpcLimits {
    fn default() -> Self {
        Self::from_capacity(MpcCapacity::baseline())
    }
}

impl MpcLimits {
    fn from_capacity(capacity: MpcCapacity) -> Self {
        assert!(capacity.is_supported(), "unsupported MPC capacity");
        Self {
            max_sent_data: capacity.max_request_bytes as usize,
            max_sent_records: capacity.max_request_records as usize,
            max_recv_data: capacity.max_response_bytes as usize,
            max_recv_records_online: capacity.max_response_records_online as usize,
        }
    }

    fn capacity(&self) -> MpcCapacity {
        MpcCapacity {
            max_request_bytes: self
                .max_sent_data
                .try_into()
                .expect("request capacity fits u32"),
            max_request_records: self
                .max_sent_records
                .try_into()
                .expect("request record capacity fits u16"),
            max_response_bytes: self
                .max_recv_data
                .try_into()
                .expect("response capacity fits u32"),
            max_response_records_online: self
                .max_recv_records_online
                .try_into()
                .expect("response record capacity fits u16"),
        }
    }
}

/// A fixed upstream identity authorized for one MPC-TLS session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPolicy {
    /// DNS host to which the Provider network layer may connect.
    pub host: String,
    /// TCP port allowed by the Provider egress policy.
    pub port: u16,
    /// DNS identity the Hub must verify in the TLS certificate.
    pub server_name: String,
}

/// Hub parameters for allocating a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionParams {
    /// Authorized upstream identity and endpoint.
    pub upstream_policy: UpstreamPolicy,
}

/// Provider parameters for binding local credential state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindCredentialParams {
    /// Opaque reference resolved only by the Provider-side credential store.
    pub credential_id: String,
    /// Authorized upstream identity and endpoint.
    pub upstream_policy: UpstreamPolicy,
}

/// Capability required to attach a dedicated channel to an existing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachChannelParams {
    /// Random capability returned only when the session is created or bound.
    pub attachment_token: String,
}

struct Session {
    owner: u64,
    binding: SessionBinding,
    busy: bool,
    attachment_token: Zeroizing<[u8; ATTACHMENT_TOKEN_SIZE]>,
    mpc_channel: Option<DuplexStream>,
    upstream_channel: Option<DeliveryTrackedStream>,
    response_channel: Option<DuplexStream>,
    engine: EngineState,
}

#[derive(Debug)]
struct AttachedChannel {
    channel: DuplexStream,
    delivery: Option<Arc<DeliveryState>>,
}

struct DeliveryCheckpoint {
    bytes: u64,
    sha256: [u8; 32],
}

struct DeliverySnapshot {
    bytes: u64,
    sha256: [u8; 32],
}

struct DeliveryStateInner {
    sent_bytes: u64,
    acked_bytes: u64,
    hasher: sha2::Sha256,
    expected: VecDeque<DeliveryCheckpoint>,
    failed: bool,
}

struct DeliveryState {
    inner: Mutex<DeliveryStateInner>,
    waker: AtomicWaker,
}

impl std::fmt::Debug for DeliveryState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.lock().map_err(|_| std::fmt::Error)?;
        formatter
            .debug_struct("DeliveryState")
            .field("sent_bytes", &state.sent_bytes)
            .field("acked_bytes", &state.acked_bytes)
            .field("pending_acks", &state.expected.len())
            .field("failed", &state.failed)
            .finish()
    }
}

impl DeliveryState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(DeliveryStateInner {
                sent_bytes: 0,
                acked_bytes: 0,
                hasher: sha2::Sha256::default(),
                expected: VecDeque::new(),
                failed: false,
            }),
            waker: AtomicWaker::new(),
        }
    }

    fn record_sent(&self, bytes: &[u8]) -> io::Result<()> {
        use sha2::Digest;

        if bytes.is_empty() {
            return Err(delivery_io_error("empty upstream delivery frame"));
        }
        let mut state = self
            .inner
            .lock()
            .map_err(|_| delivery_io_error("delivery state lock failed"))?;
        if state.failed {
            return Err(delivery_io_error("delivery path failed"));
        }
        state.sent_bytes = state
            .sent_bytes
            .checked_add(u64::try_from(bytes.len()).expect("usize fits u64"))
            .ok_or_else(|| delivery_io_error("delivery byte count overflow"))?;
        state.hasher.update(bytes);
        let sha256 = state.hasher.clone().finalize().into();
        let sent_bytes = state.sent_bytes;
        state.expected.push_back(DeliveryCheckpoint {
            bytes: sent_bytes,
            sha256,
        });
        Ok(())
    }

    fn acknowledge(&self, ack: DeliveryAck) -> io::Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| delivery_io_error("delivery state lock failed"))?;
        if state.failed {
            return Err(delivery_io_error("delivery path failed"));
        }
        let Some(expected) = state.expected.front() else {
            state.failed = true;
            drop(state);
            self.waker.wake();
            return Err(delivery_io_error("unsolicited delivery acknowledgement"));
        };
        if ack.bytes != expected.bytes || ack.sha256 != expected.sha256 {
            state.failed = true;
            drop(state);
            self.waker.wake();
            return Err(delivery_io_error("invalid delivery acknowledgement"));
        }
        state.acked_bytes = ack.bytes;
        state.expected.pop_front();
        drop(state);
        self.waker.wake();
        Ok(())
    }

    fn fail(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.failed = true;
        }
        self.waker.wake();
    }

    fn poll_acked(&self, target: u64, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let status = || {
            let state = self
                .inner
                .lock()
                .map_err(|_| delivery_io_error("delivery state lock failed"))?;
            if state.failed {
                return Err(delivery_io_error("delivery path failed"));
            }
            Ok(state.acked_bytes >= target)
        };
        match status() {
            Err(error) => return Poll::Ready(Err(error)),
            Ok(true) => return Poll::Ready(Ok(())),
            Ok(false) => {}
        }
        self.waker.register(cx.waker());
        match status() {
            Err(error) => Poll::Ready(Err(error)),
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
        }
    }

    fn poll_snapshot(
        &self,
        target: u64,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<DeliverySnapshot>> {
        use sha2::Digest;

        let status = || {
            let state = self
                .inner
                .lock()
                .map_err(|_| delivery_io_error("delivery state lock failed"))?;
            if state.failed {
                return Err(delivery_io_error("delivery path failed"));
            }
            if state.acked_bytes >= target
                && state.acked_bytes == state.sent_bytes
                && state.expected.is_empty()
            {
                return Ok(Some(DeliverySnapshot {
                    bytes: state.acked_bytes,
                    sha256: state.hasher.clone().finalize().into(),
                }));
            }
            Ok(None)
        };
        match status() {
            Err(error) => return Poll::Ready(Err(error)),
            Ok(Some(snapshot)) => return Poll::Ready(Ok(snapshot)),
            Ok(None) => {}
        }
        self.waker.register(cx.waker());
        match status() {
            Err(error) => Poll::Ready(Err(error)),
            Ok(Some(snapshot)) => Poll::Ready(Ok(snapshot)),
            Ok(None) => Poll::Pending,
        }
    }
}

fn delivery_io_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
struct DeliveryTrackedStream {
    inner: DuplexStream,
    delivery: Arc<DeliveryState>,
    written_bytes: u64,
}

impl DeliveryTrackedStream {
    fn new(inner: DuplexStream, delivery: Arc<DeliveryState>) -> Self {
        Self {
            inner,
            delivery,
            written_bytes: 0,
        }
    }
}

impl AsyncRead for DeliveryTrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for DeliveryTrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let written = match Pin::new(&mut self.inner).poll_write(cx, buffer) {
            Poll::Ready(Ok(written)) => written,
            other => return other,
        };
        match self.written_bytes.checked_add(written as u64) {
            Some(total) => {
                self.written_bytes = total;
                Poll::Ready(Ok(written))
            }
            None => {
                self.delivery.fail();
                Poll::Ready(Err(delivery_io_error("delivery byte count overflow")))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => self.delivery.poll_acked(self.written_bytes, cx),
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl Session {
    async fn shutdown(self) {
        match self.engine {
            EngineState::HubReady(engine) => engine.shutdown().await,
            EngineState::Hub13Running(mut task) => task.abort_and_wait().await,
            EngineState::ProviderRunning(engine) => engine.shutdown().await,
            _ => {}
        }
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("owner", &self.owner)
            .field("binding", &self.binding)
            .field("busy", &self.busy)
            .field("attachment_token", &"[REDACTED]")
            .field("mpc_attached", &self.mpc_channel.is_some())
            .field("upstream_attached", &self.upstream_channel.is_some())
            .field("response_attached", &self.response_channel.is_some())
            .field("engine", &self.engine)
            .finish()
    }
}

enum EngineState {
    Allocated,
    Handshaking,
    HubReady(HubEngine),
    Hub13Ready(Box<tokenhive_tls13::Hub>),
    Hub13Running(AbortTask),
    Provider13Running(Box<tls13::ProviderEngine>),
    ProviderRunning(ProviderEngine),
    Failed,
}

impl std::fmt::Debug for EngineState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Hub13Ready(_) => "Hub13Ready",
            Self::Hub13Running(_) => "Hub13Running",
            Self::Provider13Running(_) => "Provider13Running",
            Self::Allocated => "Allocated",
            Self::Handshaking => "Handshaking",
            Self::HubReady(engine) => {
                engine.validate_live_state();
                "HubReady"
            }
            Self::ProviderRunning(engine) => {
                engine.validate_live_state();
                "ProviderRunning"
            }
            Self::Failed => "Failed",
        })
    }
}

struct HubEngine {
    verifier_task: AbortTask,
    response_task: AbortTask,
    selective: SelectiveFollowerControl,
    session_runtime: TlsnSessionRuntime,
}

impl HubEngine {
    fn validate_live_state(&self) {
        let _ = (
            &self.selective,
            self.session_runtime.task.is_finished(),
            self.verifier_task.0.is_finished(),
            self.response_task.0.is_finished(),
        );
    }

    async fn shutdown(mut self) {
        self.verifier_task.abort_and_wait().await;
        self.response_task.abort_and_wait().await;
    }
}

struct ProviderEngine {
    prover_task: AbortTask,
    tls_connection: TlsConnection,
    selective: SelectiveLeaderControl,
    session_runtime: TlsnSessionRuntime,
    upstream_delivery: Arc<DeliveryState>,
}

impl ProviderEngine {
    fn validate_live_state(&self) {
        let _ = (
            &self.tls_connection,
            &self.selective,
            self.session_runtime.task.is_finished(),
            self.prover_task.0.is_finished(),
            &self.upstream_delivery,
        );
    }

    async fn shutdown(mut self) {
        self.prover_task.abort_and_wait().await;
    }
}

struct AbortTask(tokio::task::JoinHandle<()>);

impl AbortTask {
    async fn abort_and_wait(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct TlsnSessionRuntime {
    task: tokio::task::JoinHandle<()>,
    handle: tlsn::SessionHandle,
}

impl Drop for TlsnSessionRuntime {
    fn drop(&mut self) {
        self.handle.close();
        self.task.abort();
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

enum HandshakeInputs {
    Hub {
        policy: UpstreamPolicy,
        mpc_channel: DuplexStream,
        response_channel: DuplexStream,
    },
    Provider {
        policy: UpstreamPolicy,
        mpc_channel: DuplexStream,
        upstream_channel: DeliveryTrackedStream,
    },
}

enum HandshakeOutput {
    Hub13(Box<tokenhive_tls13::Hub>),
    Provider13(Box<tls13::ProviderEngine>),
    Hub(HubEngine),
    Provider(ProviderEngine),
}

#[derive(Debug, thiserror::Error)]
enum EngineError {
    #[error("TLSNotary operation failed during {0}")]
    Tlsn(&'static str),
    #[error("TLSNotary commitment configuration did not match local limits")]
    ConfigMismatch,
    #[error("authenticated server traffic keys were not decoded")]
    MissingServerKeys,
    #[error("MPC TLS handshake timed out")]
    Timeout,
}

fn tlsn_stage_error(stage: &'static str, error: impl std::fmt::Debug) -> EngineError {
    if std::env::var_os("TOKENHIVE_MPC_BENCH_CAPACITY_BYTES").is_some() {
        eprintln!("tokenhive_mpc_benchmark_error stage={stage} error={error:?}");
    }
    EngineError::Tlsn(stage)
}

#[derive(Debug)]
enum SessionBinding {
    Hub(UpstreamPolicy),
    Provider {
        credential_id: String,
        upstream_policy: UpstreamPolicy,
    },
}

impl SessionBinding {
    fn validate_stored_values(&self) {
        match self {
            Self::Hub(policy) => debug_assert!(!policy.server_name.is_empty()),
            Self::Provider {
                credential_id,
                upstream_policy,
            } => {
                debug_assert!(!credential_id.is_empty());
                debug_assert!(!upstream_policy.server_name.is_empty());
            }
        }
    }
}

#[derive(Debug, Default)]
struct Registry {
    next_owner: u64,
    sessions: HashMap<u64, Session>,
}

/// Shared role-specific sidecar runtime.
#[derive(Debug)]
pub struct Runtime {
    tls13: bool,
    role: Role,
    root_store: RootCertStore,
    limits: MpcLimits,
    credential_resolver: Arc<dyn CredentialResolver>,
    registry: Mutex<Registry>,
}

impl Runtime {
    /// Creates an empty runtime for one immutable sidecar role.
    pub fn new(role: Role) -> Self {
        Self::with_credential_resolver(role, Arc::new(EmptyCredentialResolver))
    }

    /// Creates a runtime backed by a Provider-local credential resolver.
    pub fn with_credential_resolver(
        role: Role,
        credential_resolver: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self::with_capacity_and_credential_resolver(
            role,
            MpcCapacity::baseline(),
            credential_resolver,
        )
    }

    fn with_capacity_and_credential_resolver(
        role: Role,
        capacity: MpcCapacity,
        credential_resolver: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self {
            role,
            tls13: false,
            root_store: RootCertStore::mozilla(),
            limits: MpcLimits::from_capacity(capacity),
            credential_resolver,
            registry: Mutex::new(Registry::default()),
        }
    }

    fn allocate_owner(&self) -> Result<u64, ServiceError> {
        let mut registry = self.registry.lock().map_err(|_| ServiceError::Poisoned)?;
        registry.next_owner = registry
            .next_owner
            .checked_add(1)
            .ok_or(ServiceError::OwnerExhausted)?;
        Ok(registry.next_owner)
    }

    async fn release_owner(&self, owner: u64) {
        let sessions = if let Ok(mut registry) = self.registry.lock() {
            let session_ids: Vec<_> = registry
                .sessions
                .iter()
                .filter_map(|(id, session)| (session.owner == owner).then_some(*id))
                .collect();
            session_ids
                .into_iter()
                .filter_map(|id| registry.sessions.remove(&id))
                .collect()
        } else {
            Vec::new()
        };
        for session in sessions {
            session.shutdown().await;
        }
    }

    async fn dispatch(
        &self,
        owner: u64,
        session_id: u64,
        command: RpcCommand,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        match command.operation {
            Operation::CreateSession => {
                self.create_session(owner, session_id, command.request_id, command.params)
            }
            Operation::BindCredential => {
                self.bind_credential(owner, session_id, command.request_id, command.params)
            }
            Operation::CloseSession | Operation::DestroySession => {
                self.remove_session(owner, session_id, command.request_id)
                    .await
            }
            Operation::RunHandshake => {
                self.run_handshake(owner, session_id, command.request_id, command.params)
                    .await
            }
            _ => {
                self.dispatch_engine_operation(owner, session_id, command, stream)
                    .await
            }
        }
    }

    fn create_session(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
    ) -> RpcResult {
        let params: CreateSessionParams = match parse_params(params) {
            Ok(params) => params,
            Err(result) => return result(request_id),
        };
        if let Err(code) = validate_upstream(&params.upstream_policy) {
            return invalid_params(request_id, code);
        }
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return internal_error(request_id),
        };
        if registry.sessions.contains_key(&session_id) {
            return RpcResult::error(request_id, "session_exists", "session already exists");
        }
        let attachment_token = Zeroizing::new(rand::random());
        let encoded_token = encode_token(&attachment_token);
        registry.sessions.insert(
            session_id,
            Session {
                owner,
                binding: SessionBinding::Hub(params.upstream_policy),
                busy: false,
                attachment_token,
                mpc_channel: None,
                upstream_channel: None,
                response_channel: None,
                engine: EngineState::Allocated,
            },
        );
        RpcResult::ok(
            request_id,
            Some(json!({
                "state": "created",
                "attachment_token": encoded_token,
            })),
        )
    }

    fn bind_credential(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
    ) -> RpcResult {
        let params: BindCredentialParams = match parse_params(params) {
            Ok(params) => params,
            Err(result) => return result(request_id),
        };
        if !valid_credential_id(&params.credential_id) {
            return invalid_params(request_id, "invalid_credential_id");
        }
        if let Err(code) = validate_upstream(&params.upstream_policy) {
            return invalid_params(request_id, code);
        }
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return internal_error(request_id),
        };
        if registry.sessions.contains_key(&session_id) {
            return RpcResult::error(request_id, "session_exists", "session already exists");
        }
        let attachment_token = Zeroizing::new(rand::random());
        let encoded_token = encode_token(&attachment_token);
        registry.sessions.insert(
            session_id,
            Session {
                owner,
                binding: SessionBinding::Provider {
                    credential_id: params.credential_id,
                    upstream_policy: params.upstream_policy,
                },
                busy: false,
                attachment_token,
                mpc_channel: None,
                upstream_channel: None,
                response_channel: None,
                engine: EngineState::Allocated,
            },
        );
        RpcResult::ok(
            request_id,
            Some(json!({
                "state": "credential_bound",
                "attachment_token": encoded_token,
            })),
        )
    }

    fn attach_channel(
        &self,
        session_id: u64,
        request_id: u64,
        operation: Operation,
        params: Value,
    ) -> Result<AttachedChannel, RpcResult> {
        let params: AttachChannelParams = serde_json::from_value(params)
            .map_err(|_| invalid_params(request_id, "invalid_params"))?;
        let supplied_token = decode_token(&params.attachment_token)
            .ok_or_else(|| attachment_rejected(request_id))?;

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| internal_error(request_id))?;
        let session = registry
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| attachment_rejected(request_id))?;
        if !constant_time_eq(&supplied_token, &session.attachment_token) {
            return Err(attachment_rejected(request_id));
        }
        if session.busy {
            return Err(RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            ));
        }

        let (engine_channel, rpc_channel) = tokio::io::duplex(ATTACHMENT_BUFFER_SIZE);
        let delivery = match operation {
            Operation::AttachMpcChannel => {
                if session.mpc_channel.is_some() {
                    return Err(attachment_exists(request_id));
                }
                session.mpc_channel = Some(engine_channel);
                None
            }
            Operation::AttachUpstreamChannel => {
                if session.upstream_channel.is_some() {
                    return Err(attachment_exists(request_id));
                }
                let delivery = Arc::new(DeliveryState::new());
                session.upstream_channel = Some(DeliveryTrackedStream::new(
                    engine_channel,
                    Arc::clone(&delivery),
                ));
                Some(delivery)
            }
            Operation::AttachResponseChannel => {
                if session.response_channel.is_some() {
                    return Err(attachment_exists(request_id));
                }
                session.response_channel = Some(engine_channel);
                None
            }
            _ => return Err(invalid_params(request_id, "invalid_operation")),
        };
        Ok(AttachedChannel {
            channel: rpc_channel,
            delivery,
        })
    }

    async fn remove_session(&self, owner: u64, session_id: u64, request_id: u64) -> RpcResult {
        let session = match self.take_session_for_removal(owner, session_id, request_id) {
            Ok(session) => session,
            Err(result) => return result,
        };
        session.shutdown().await;
        RpcResult::ok(request_id, Some(json!({"state": "destroyed"})))
    }

    fn take_session_for_removal(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
    ) -> Result<Session, RpcResult> {
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return Err(internal_error(request_id)),
        };
        let Some(session) = registry.sessions.get(&session_id) else {
            return Err(RpcResult::error(
                request_id,
                "session_not_found",
                "session does not exist",
            ));
        };
        if session.owner != owner {
            return Err(RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            ));
        }
        if session.busy {
            return Err(RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            ));
        }
        Ok(registry
            .sessions
            .remove(&session_id)
            .expect("session existence was checked above"))
    }

    async fn run_handshake(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
    ) -> RpcResult {
        if serde_json::from_value::<EmptyParams>(params).is_err() {
            return invalid_params(request_id, "invalid_params");
        }
        let inputs = match self.take_handshake_inputs(owner, session_id, request_id) {
            Ok(inputs) => inputs,
            Err(result) => return result,
        };
        let handshake = async {
            if self.tls13 {
                return self.handshake13(inputs).await;
            }
            match inputs {
                HandshakeInputs::Hub {
                    policy,
                    mpc_channel,
                    response_channel,
                } => run_hub_handshake(
                    policy,
                    mpc_channel,
                    response_channel,
                    self.root_store.clone(),
                    self.limits.clone(),
                )
                .await
                .map(HandshakeOutput::Hub),
                HandshakeInputs::Provider {
                    policy,
                    mpc_channel,
                    upstream_channel,
                } => run_provider_handshake(
                    policy,
                    mpc_channel,
                    upstream_channel,
                    self.root_store.clone(),
                    self.limits.clone(),
                )
                .await
                .map(HandshakeOutput::Provider),
            }
        };
        let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .unwrap_or(Err(EngineError::Timeout));

        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return internal_error(request_id),
        };
        let Some(session) = registry.sessions.get_mut(&session_id) else {
            return RpcResult::error(
                request_id,
                "session_not_found",
                "session was destroyed during handshake",
            );
        };
        if session.owner != owner {
            session.engine = EngineState::Failed;
            session.busy = false;
            return internal_error(request_id);
        }
        session.busy = false;
        match outcome {
            Ok(HandshakeOutput::Hub13(engine)) => {
                session.engine = EngineState::Hub13Ready(engine);
                RpcResult::ok(
                    request_id,
                    Some(
                        json!({"state":"ready", "tls_version":"1.3", "upstream_authenticated":true}),
                    ),
                )
            }
            Ok(HandshakeOutput::Provider13(engine)) => {
                session.engine = EngineState::Provider13Running(engine);
                RpcResult::ok(
                    request_id,
                    Some(json!({"state":"handshake_running", "tls_version":"1.3"})),
                )
            }
            Ok(HandshakeOutput::Hub(engine)) => {
                session.engine = EngineState::HubReady(engine);
                RpcResult::ok(
                    request_id,
                    Some(json!({
                        "state": "ready",
                        "tls_version": "1.2",
                        "upstream_authenticated": true,
                    })),
                )
            }
            Ok(HandshakeOutput::Provider(engine)) => {
                session.engine = EngineState::ProviderRunning(engine);
                RpcResult::ok(
                    request_id,
                    Some(json!({
                        "state": "handshake_running",
                        "tls_version": "1.2",
                    })),
                )
            }
            Err(_error) => {
                session.engine = EngineState::Failed;
                RpcResult::error(request_id, "handshake_failed", "MPC TLS handshake failed")
            }
        }
    }

    fn take_handshake_inputs(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
    ) -> Result<HandshakeInputs, RpcResult> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| internal_error(request_id))?;
        let session = registry.sessions.get_mut(&session_id).ok_or_else(|| {
            RpcResult::error(request_id, "session_not_found", "session does not exist")
        })?;
        if session.owner != owner {
            return Err(RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            ));
        }
        if session.busy {
            return Err(RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            ));
        }
        if !matches!(session.engine, EngineState::Allocated) {
            return Err(RpcResult::error(
                request_id,
                "invalid_state",
                "session cannot start another handshake",
            ));
        }
        let Some(mpc_channel) = session.mpc_channel.take() else {
            return Err(RpcResult::error(
                request_id,
                "missing_attachment",
                "MPC channel is not attached",
            ));
        };
        let policy = match &session.binding {
            SessionBinding::Hub(policy) => policy.clone(),
            SessionBinding::Provider {
                upstream_policy, ..
            } => upstream_policy.clone(),
        };
        let inputs = match self.role {
            Role::Hub => {
                let Some(response_channel) = session.response_channel.take() else {
                    session.mpc_channel = Some(mpc_channel);
                    return Err(RpcResult::error(
                        request_id,
                        "missing_attachment",
                        "response channel is not attached",
                    ));
                };
                HandshakeInputs::Hub {
                    policy,
                    mpc_channel,
                    response_channel,
                }
            }
            Role::Provider => {
                let Some(upstream_channel) = session.upstream_channel.take() else {
                    session.mpc_channel = Some(mpc_channel);
                    return Err(RpcResult::error(
                        request_id,
                        "missing_attachment",
                        "upstream channel is not attached",
                    ));
                };
                HandshakeInputs::Provider {
                    policy,
                    mpc_channel,
                    upstream_channel,
                }
            }
        };
        session.busy = true;
        session.engine = EngineState::Handshaking;
        Ok(inputs)
    }

    async fn dispatch_engine_operation(
        &self,
        owner: u64,
        session_id: u64,
        command: RpcCommand,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        match command.operation {
            Operation::EncryptRequest => self.prepare_hub_request(
                owner,
                session_id,
                command.request_id,
                command.params,
                stream,
            ),
            Operation::ContributeRequestEncryption => {
                self.contribute_provider_request(
                    owner,
                    session_id,
                    command.request_id,
                    command.params,
                    stream,
                )
                .await
            }
            Operation::FeedServerRecords => RpcResult::error(
                command.request_id,
                "not_implemented",
                "server record dispatch is not implemented",
            ),
            _ => invalid_params(command.request_id, "invalid_operation"),
        }
    }

    fn prepare_hub_request(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        if self.tls13 {
            return self.prepare_hub13(owner, session_id, request_id, params, stream);
        }
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return internal_error(request_id),
        };
        let Some(session) = registry.sessions.get_mut(&session_id) else {
            return RpcResult::error(request_id, "session_not_found", "session does not exist");
        };
        if session.owner != owner {
            return RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            );
        }
        if session.busy {
            return RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            );
        }
        session.binding.validate_stored_values();
        let params = match serde_json::from_value::<SelectiveRequestParams>(params) {
            Ok(params) => params,
            Err(_) => return invalid_params(request_id, "invalid_params"),
        };
        let (Some(request), SessionBinding::Hub(policy)) = (stream, &session.binding) else {
            return invalid_params(request_id, "invalid_params");
        };
        let validated = match validate_request(&params, &policy.server_name, &request) {
            Ok(validated) => validated,
            Err(_) => return invalid_params(request_id, "invalid_canonical_request"),
        };
        let EngineState::HubReady(engine) = &session.engine else {
            return RpcResult::error(
                request_id,
                "invalid_state",
                "Hub MPC-TLS engine is not ready",
            );
        };
        if engine.response_task.0.is_finished()
            || engine.verifier_task.0.is_finished()
            || engine.session_runtime.task.is_finished()
        {
            return RpcResult::error(
                request_id,
                "response_path_closed",
                "authenticated response path is closed",
            );
        }
        let ranges = validated
            .layout
            .spans
            .iter()
            .map(|span| span.offset..span.offset + span.length)
            .collect();
        if engine.selective.prepare(request, ranges).is_err() {
            return RpcResult::error(
                request_id,
                "selective_request_pending",
                "a selective request is already pending",
            );
        }
        RpcResult::ok(
            request_id,
            Some(json!({
                "state": "request_prepared",
                "task_id": params.task_id,
                "requested_model": validated.model,
                "streaming": validated.streaming,
                "public_request_hash": encode_hash(&validated.hash),
            })),
        )
    }

    async fn contribute_provider_request(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        if self.tls13 {
            return self
                .contribute_provider13(owner, session_id, request_id, params, stream)
                .await;
        }
        let prepared =
            match self.take_provider_request(owner, session_id, request_id, params, stream) {
                Ok(prepared) => prepared,
                Err(result) => return result,
            };
        let ProviderRequest {
            mut engine,
            request,
            task_id,
            request_hash,
            requested_model,
            streaming,
        } = prepared;
        let operation = async {
            let before =
                futures::future::poll_fn(|cx| engine.upstream_delivery.poll_snapshot(0, cx))
                    .await
                    .map_err(|_| "delivery_state_failed")?;
            let record_count = request.len().div_ceil(TLS_PLAINTEXT_FRAGMENT_SIZE);
            let request_wire_bytes = u64::try_from(request.len())
                .expect("request length fits u64")
                .checked_add(
                    u64::try_from(record_count)
                        .expect("record count fits u64")
                        .checked_mul(TLS12_AES_GCM_RECORD_OVERHEAD)
                        .ok_or("delivery_state_failed")?,
                )
                .ok_or("delivery_state_failed")?;
            let delivery_target = before
                .bytes
                .checked_add(request_wire_bytes)
                .ok_or("delivery_state_failed")?;
            // Large writes are naturally fragmented at the TLS plaintext
            // limit. Only the first record overlaps the credential span;
            // following records use the public keystream fast path.
            FuturesAsyncWriteExt::write_all(&mut engine.tls_connection, request.as_slice())
                .await
                .map_err(|_| "engine_io_failed")?;
            FuturesAsyncWriteExt::flush(&mut engine.tls_connection)
                .await
                .map_err(|_| "engine_io_failed")?;
            let delivery_state = Arc::clone(&engine.upstream_delivery);
            let delivery =
                futures::future::poll_fn(|cx| delivery_state.poll_snapshot(delivery_target, cx));
            let after = tokio::select! {
                result = delivery => result.map_err(|_| "delivery_state_failed")?,
                _ = &mut engine.prover_task.0 => return Err("engine_io_failed"),
            };
            let request_bytes = after
                .bytes
                .checked_sub(before.bytes)
                .filter(|bytes| *bytes != 0)
                .ok_or("delivery_state_failed")?;
            Ok::<_, &'static str>((after, request_bytes))
        };
        let operation = tokio::time::timeout(REQUEST_DELIVERY_TIMEOUT, operation)
            .await
            .map_err(|_| "delivery_timeout")
            .and_then(|result| result);

        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(_) => return internal_error(request_id),
        };
        let Some(session) = registry.sessions.get_mut(&session_id) else {
            return RpcResult::error(request_id, "session_not_found", "session does not exist");
        };
        if session.owner != owner {
            return RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            );
        }
        session.busy = false;
        match operation {
            Ok((delivery, request_delivery_bytes)) => {
                session.engine = EngineState::ProviderRunning(engine);
                RpcResult::ok(
                    request_id,
                    Some(json!({
                        "state": "request_delivered",
                        "task_id": task_id,
                        "requested_model": requested_model,
                        "streaming": streaming,
                        "public_request_hash": encode_hash(&request_hash),
                        "upstream_delivery": {
                            "cumulative_bytes": delivery.bytes,
                            "request_bytes": request_delivery_bytes,
                            "sha256": encode_hash(&delivery.sha256),
                        },
                    })),
                )
            }
            Err(code) => {
                session.engine = EngineState::Failed;
                RpcResult::error(request_id, code, "selective request encryption failed")
            }
        }
    }

    fn take_provider_request(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> Result<ProviderRequest, RpcResult> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| internal_error(request_id))?;
        let session = registry.sessions.get_mut(&session_id).ok_or_else(|| {
            RpcResult::error(request_id, "session_not_found", "session does not exist")
        })?;
        if session.owner != owner {
            return Err(RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            ));
        }
        if session.busy {
            return Err(RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            ));
        }
        session.binding.validate_stored_values();
        let params = serde_json::from_value::<SelectiveRequestParams>(params)
            .map_err(|_| invalid_params(request_id, "invalid_params"))?;
        let (request, credential_id, policy) = match (stream, &session.binding) {
            (
                Some(request),
                SessionBinding::Provider {
                    credential_id,
                    upstream_policy,
                },
            ) => (request, credential_id, upstream_policy),
            _ => return Err(invalid_params(request_id, "invalid_params")),
        };
        let validated = validate_request(&params, &policy.server_name, &request)
            .map_err(|_| invalid_params(request_id, "invalid_canonical_request"))?;
        let credential = self
            .credential_resolver
            .resolve(credential_id)
            .ok_or_else(|| {
                RpcResult::error(
                    request_id,
                    "credential_not_found",
                    "bound credential could not be resolved",
                )
            })?;
        if credential.len() != params.credential_length {
            return Err(RpcResult::error(
                request_id,
                "credential_length_mismatch",
                "bound credential length does not match request metadata",
            ));
        }
        let ranges: Vec<_> = validated
            .layout
            .spans
            .iter()
            .map(|span| span.offset..span.offset + span.length)
            .collect();
        let credential_range = ranges
            .first()
            .expect("canonical adapter always emits one credential span")
            .clone();
        let mut request = Zeroizing::new(request);
        request[credential_range].copy_from_slice(&credential);

        let EngineState::ProviderRunning(engine) = &session.engine else {
            return Err(RpcResult::error(
                request_id,
                "invalid_state",
                "Provider MPC-TLS engine is not running",
            ));
        };
        engine
            .selective
            .prepare(request.len(), ranges)
            .map_err(|_| {
                RpcResult::error(
                    request_id,
                    "selective_request_pending",
                    "a selective request is already pending",
                )
            })?;
        let EngineState::ProviderRunning(engine) =
            std::mem::replace(&mut session.engine, EngineState::Handshaking)
        else {
            unreachable!("Provider engine state was checked above")
        };
        session.busy = true;
        Ok(ProviderRequest {
            engine,
            request,
            task_id: params.task_id,
            request_hash: validated.hash,
            requested_model: validated.model,
            streaming: validated.streaming,
        })
    }
}

struct ProviderRequest {
    engine: ProviderEngine,
    request: Zeroizing<Vec<u8>>,
    task_id: String,
    request_hash: [u8; 32],
    requested_model: String,
    streaming: bool,
}

fn encode_hash(hash: &[u8; 32]) -> String {
    use std::fmt::Write;

    hash.iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

fn mpc_config(limits: &MpcLimits) -> Result<MpcTlsConfig, EngineError> {
    MpcTlsConfig::builder()
        .max_sent_data(limits.max_sent_data)
        .max_sent_records(limits.max_sent_records)
        .max_recv_data(limits.max_recv_data)
        .max_recv_records_online(limits.max_recv_records_online)
        .build()
        .map_err(|_| EngineError::Tlsn("configuration"))
}

fn config_matches(config: &MpcTlsConfig, limits: &MpcLimits) -> bool {
    config.max_sent_data() == limits.max_sent_data
        && config.max_sent_records() == Some(limits.max_sent_records)
        && config.max_recv_data() == limits.max_recv_data
        && config.max_recv_records_online() == Some(limits.max_recv_records_online)
}

fn server_name(policy: &UpstreamPolicy) -> Result<ServerName, EngineError> {
    Ok(ServerName::Dns(
        policy
            .server_name
            .as_str()
            .try_into()
            .map_err(|_| EngineError::Tlsn("verifier configuration"))?,
    ))
}

fn spawn_session_driver(
    driver: tlsn::SessionDriver<Compat<DuplexStream>>,
    handle: tlsn::SessionHandle,
) -> TlsnSessionRuntime {
    let task = tokio::spawn(async move {
        let _ = driver.await;
    });
    TlsnSessionRuntime { task, handle }
}

async fn run_hub_handshake(
    policy: UpstreamPolicy,
    mpc_channel: DuplexStream,
    response_channel: DuplexStream,
    root_store: RootCertStore,
    limits: MpcLimits,
) -> Result<HubEngine, EngineError> {
    let _phase = tokenhive_tls13::diagnostics::Phase::new(false, "tls12_handshake");
    let mut session = TlsnSession::new(mpc_channel.compat());
    let verifier = session
        .new_verifier(
            VerifierConfig::builder()
                .root_store(root_store)
                .build()
                .map_err(|_| EngineError::Tlsn("verifier configuration"))?,
        )
        .map_err(|_| EngineError::Tlsn("verifier creation"))?;
    let (driver, handle) = session.split();
    let session_runtime = spawn_session_driver(driver, handle);

    let VerifierCommitStart::Mpc(verifier) = verifier
        .commit()
        .await
        .map_err(|_| EngineError::Tlsn("verifier commitment"))?
    else {
        return Err(EngineError::ConfigMismatch);
    };
    if !config_matches(verifier.config(), &limits) {
        let _ = verifier.reject(None).await;
        return Err(EngineError::ConfigMismatch);
    }
    let phase = tokenhive_tls13::diagnostics::Phase::new(false, "tls12_preprocessing");
    let mut verifier = verifier
        .accept()
        .await
        .map_err(|error| tlsn_stage_error("verifier_preprocessing", error))?;
    phase.finish();
    let selective = verifier.selective_control();
    let server_records = verifier
        .take_server_records()
        .map_err(|_| EngineError::Tlsn("server record setup"))?;
    selective.require_selective();
    let authentication = verifier
        .authenticate_upstream(server_name(&policy)?)
        .map_err(|_| EngineError::Tlsn("upstream authentication setup"))?;
    let verifier_task = AbortTask(tokio::spawn(async move {
        let _ = verifier.run().await;
    }));
    let phase = tokenhive_tls13::diagnostics::Phase::new(false, "tls12_upstream_authentication");
    let mut release = authentication
        .wait()
        .await
        .map_err(|_| EngineError::Tlsn("upstream authentication"))?;
    phase.finish();
    let keys = release
        .try_take()
        .map_err(|_| EngineError::Tlsn("server key release"))?
        .ok_or(EngineError::MissingServerKeys)?;

    let response_task = AbortTask(tokio::spawn(async move {
        let _ = pump_authenticated_response(server_records, keys, response_channel).await;
    }));

    _phase.finish();
    Ok(HubEngine {
        response_task,
        selective,
        session_runtime,
        verifier_task,
    })
}

async fn run_provider_handshake(
    policy: UpstreamPolicy,
    mpc_channel: DuplexStream,
    upstream_channel: DeliveryTrackedStream,
    root_store: RootCertStore,
    limits: MpcLimits,
) -> Result<ProviderEngine, EngineError> {
    let _phase = tokenhive_tls13::diagnostics::Phase::new(true, "tls12_handshake");
    let upstream_delivery = Arc::clone(&upstream_channel.delivery);
    let mut session = TlsnSession::new(mpc_channel.compat());
    let prover = session
        .new_prover(
            ProverConfig::builder()
                .build()
                .map_err(|_| EngineError::Tlsn("prover configuration"))?,
        )
        .map_err(|_| EngineError::Tlsn("prover creation"))?;
    let (driver, handle) = session.split();
    let session_runtime = spawn_session_driver(driver, handle);
    let phase = tokenhive_tls13::diagnostics::Phase::new(true, "tls12_preprocessing");
    let prover = prover
        .commit(mpc_config(&limits)?)
        .await
        .map_err(|error| tlsn_stage_error("prover_preprocessing", error))?;
    phase.finish();
    let expected_server = server_name(&policy)?;
    let (tls_connection, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(expected_server)
                .root_store(root_store)
                .build()
                .map_err(|_| EngineError::Tlsn("TLS client configuration"))?,
            upstream_channel.compat(),
        )
        .map_err(|_| EngineError::Tlsn("TLS client connection"))?;
    let selective = prover
        .control()
        .selective()
        .ok_or(EngineError::Tlsn("selective control"))?;
    selective.require_selective();
    let prover_task = AbortTask(tokio::spawn(async move {
        let _ = prover.into_future().await;
    }));

    _phase.finish();
    Ok(ProviderEngine {
        tls_connection,
        selective,
        session_runtime,
        prover_task,
        upstream_delivery,
    })
}

fn parse_params<T: DeserializeOwned>(
    params: Value,
) -> Result<T, Box<dyn FnOnce(u64) -> RpcResult + Send>> {
    serde_json::from_value(params).map_err(|_| {
        Box::new(|request_id| invalid_params(request_id, "invalid_params"))
            as Box<dyn FnOnce(u64) -> RpcResult + Send>
    })
}

fn invalid_params(request_id: u64, code: &'static str) -> RpcResult {
    RpcResult::error(request_id, code, "operation parameters are invalid")
}

fn internal_error(request_id: u64) -> RpcResult {
    RpcResult::error(
        request_id,
        "internal_error",
        "sidecar internal state failed",
    )
}

fn attachment_rejected(request_id: u64) -> RpcResult {
    RpcResult::error(
        request_id,
        "attachment_rejected",
        "attachment capability was rejected",
    )
}

fn attachment_exists(request_id: u64) -> RpcResult {
    RpcResult::error(
        request_id,
        "attachment_exists",
        "channel is already attached",
    )
}

fn encode_token(token: &[u8; ATTACHMENT_TOKEN_SIZE]) -> String {
    use std::fmt::Write;

    token.iter().fold(
        String::with_capacity(ATTACHMENT_TOKEN_SIZE * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}

fn decode_token(value: &str) -> Option<Zeroizing<[u8; ATTACHMENT_TOKEN_SIZE]>> {
    if value.len() != ATTACHMENT_TOKEN_SIZE * 2 || !value.is_ascii() {
        return None;
    }
    let mut token = Zeroizing::new([0u8; ATTACHMENT_TOKEN_SIZE]);
    for (index, output) in token.iter_mut().enumerate() {
        let start = index * 2;
        *output = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(token)
}

fn constant_time_eq(
    left: &[u8; ATTACHMENT_TOKEN_SIZE],
    right: &[u8; ATTACHMENT_TOKEN_SIZE],
) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn validate_upstream(policy: &UpstreamPolicy) -> Result<(), &'static str> {
    if policy.port == 0 {
        return Err("invalid_upstream_port");
    }
    if !valid_dns_name(&policy.host) || !valid_dns_name(&policy.server_name) {
        return Err("invalid_upstream_identity");
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_ID_SIZE
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn operation_has_input_stream(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::EncryptRequest
            | Operation::FeedServerRecords
            | Operation::ContributeRequestEncryption
    )
}

async fn serve_connection(stream: UnixStream, runtime: Arc<Runtime>) -> Result<(), ServiceError> {
    let owner = runtime.allocate_owner()?;
    let result = serve_connection_inner(stream, Arc::clone(&runtime), owner).await;
    runtime.release_owner(owner).await;
    result
}

async fn serve_connection_inner(
    stream: UnixStream,
    runtime: Arc<Runtime>,
    owner: u64,
) -> Result<(), ServiceError> {
    let (read, write) = stream.into_split();
    let mut reader = FrameReader::new(read);
    let mut writer = FrameWriter::new(write);
    accept_hello(
        &mut reader,
        &mut writer,
        if runtime.tls13 {
            Capabilities::tls13_with_capacity(runtime.role, runtime.limits.capacity())
        } else {
            Capabilities::selective_mpc_with_capacity(runtime.role, runtime.limits.capacity())
        },
    )
    .await?;

    let mut request_ids = HashSet::new();
    loop {
        let (session_id, command) = match read_command(&mut reader, runtime.role).await {
            Ok(command) => command,
            Err(RpcError::Wire(tokenhive_sidecar_protocol::WireError::Io(error)))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !request_ids.insert(command.request_id) {
            write_result(
                &mut writer,
                session_id,
                &RpcResult::error(
                    command.request_id,
                    "duplicate_request_id",
                    "request_id was already used on this connection",
                ),
            )
            .await?;
            continue;
        }

        if matches!(
            command.operation,
            Operation::AttachMpcChannel
                | Operation::AttachUpstreamChannel
                | Operation::AttachResponseChannel
        ) {
            match runtime.attach_channel(
                session_id,
                command.request_id,
                command.operation,
                command.params,
            ) {
                Ok(channel) => {
                    write_result(
                        &mut writer,
                        session_id,
                        &RpcResult::ok(command.request_id, Some(json!({"state": "attached"}))),
                    )
                    .await?;
                    return pump_attachment(reader, writer, channel, session_id).await;
                }
                Err(result) => {
                    write_result(&mut writer, session_id, &result).await?;
                    continue;
                }
            }
        }

        let stream = if operation_has_input_stream(command.operation) {
            match read_stream(&mut reader, session_id).await? {
                StreamInput::Complete(bytes) => Some(bytes),
                StreamInput::Cancelled(_) => {
                    write_result(
                        &mut writer,
                        session_id,
                        &RpcResult::error(
                            command.request_id,
                            "operation_cancelled",
                            "operation was cancelled by the client",
                        ),
                    )
                    .await?;
                    continue;
                }
            }
        } else {
            None
        };
        let result = runtime.dispatch(owner, session_id, command, stream).await;
        write_result(&mut writer, session_id, &result).await?;
    }
}

async fn pump_attachment<R, W>(
    mut reader: FrameReader<R>,
    mut writer: FrameWriter<W>,
    attachment: AttachedChannel,
    session_id: u64,
) -> Result<(), ServiceError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let AttachedChannel { channel, delivery } = attachment;
    let (mut channel_read, mut channel_write) = tokio::io::split(channel);
    let incoming = async {
        loop {
            let frame = reader.read_frame().await.map_err(RpcError::from)?;
            if frame.flags != 0 || frame.session_id != session_id {
                return Err(ServiceError::Rpc(RpcError::InvalidFrame(
                    "attachment frame has invalid flags or session",
                )));
            }
            match frame.frame_type {
                FrameType::SidecarStream if !frame.payload.is_empty() => {
                    channel_write.write_all(&frame.payload).await?;
                }
                FrameType::SidecarStreamEnd if frame.payload.is_empty() => {
                    channel_write.shutdown().await?;
                    return Ok(());
                }
                FrameType::DeliveryAck if delivery.is_some() => {
                    let ack = DeliveryAck::decode(&frame.payload).map_err(|_| {
                        ServiceError::Rpc(RpcError::InvalidFrame(
                            "invalid delivery acknowledgement payload",
                        ))
                    })?;
                    delivery
                        .as_ref()
                        .expect("delivery mode was checked")
                        .acknowledge(ack)?;
                }
                _ => {
                    return Err(ServiceError::Rpc(RpcError::InvalidFrame(
                        "invalid attachment data frame",
                    )));
                }
            }
        }
    };
    let outgoing = async {
        let mut buffer = vec![0u8; tokenhive_sidecar_protocol::MAX_DATA_FRAME_SIZE];
        loop {
            let size = channel_read.read(&mut buffer).await?;
            if size == 0 {
                writer
                    .write_frame(FrameType::SidecarStreamEnd, 0, session_id, &[])
                    .await
                    .map_err(RpcError::from)?;
                return Ok::<(), ServiceError>(());
            }
            if let Some(delivery) = &delivery {
                delivery.record_sent(&buffer[..size])?;
            }
            writer
                .write_frame(FrameType::SidecarStream, 0, session_id, &buffer[..size])
                .await
                .map_err(RpcError::from)?;
        }
    };
    let result = tokio::try_join!(incoming, outgoing).map(|_| ());
    if result.is_err()
        && let Some(delivery) = &delivery
    {
        delivery.fail();
    }
    result
}

/// Bound Unix sidecar server. The socket path is removed on a clean drop only
/// if it still identifies the socket created by this instance.
pub struct SidecarServer {
    listener: UnixListener,
    runtime: Arc<Runtime>,
    _socket_guard: SocketPathGuard,
}

impl SidecarServer {
    /// Binds a new mode-0600 Unix socket, refusing any existing path.
    pub fn bind(path: impl AsRef<Path>, role: Role) -> Result<Self, ServiceError> {
        Self::bind_with_capacity(path, role, MpcCapacity::baseline())
    }

    /// Binds a sidecar with an exact supported MPC capacity profile.
    pub fn bind_with_capacity(
        path: impl AsRef<Path>,
        role: Role,
        capacity: MpcCapacity,
    ) -> Result<Self, ServiceError> {
        Self::bind_with_credential_resolver_and_capacity(
            path,
            role,
            Arc::new(EmptyCredentialResolver),
            capacity,
        )
    }

    /// Binds a sidecar with a Provider-local credential resolver.
    ///
    /// Hub deployments should use [`SidecarServer::bind`]. The resolver is
    /// called only by the Provider request contribution path.
    pub fn bind_with_credential_resolver(
        path: impl AsRef<Path>,
        role: Role,
        credential_resolver: Arc<dyn CredentialResolver>,
    ) -> Result<Self, ServiceError> {
        Self::bind_with_credential_resolver_and_capacity(
            path,
            role,
            credential_resolver,
            MpcCapacity::baseline(),
        )
    }

    /// Binds a credential-resolving sidecar with an exact MPC capacity profile.
    pub fn bind_with_credential_resolver_and_capacity(
        path: impl AsRef<Path>,
        role: Role,
        credential_resolver: Arc<dyn CredentialResolver>,
        capacity: MpcCapacity,
    ) -> Result<Self, ServiceError> {
        if !capacity.is_supported() {
            return Err(std::io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported MPC capacity",
            )
            .into());
        }
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(ServiceError::InvalidSocketPath);
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(ServiceError::InvalidSocketPath)?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir()
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ServiceError::InsecureSocketDirectory(parent.to_owned()));
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(ServiceError::SocketPathExists(path.to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let guard = SocketPathGuard {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            runtime: Arc::new(Runtime::with_capacity_and_credential_resolver(
                role,
                capacity,
                credential_resolver,
            )),
            _socket_guard: guard,
        })
    }

    /// Selects the TLS 1.3 engine before accepting any connections.
    /// TLS 1.2 remains the default; this does not enable protocol fallback.
    pub fn with_tls13(mut self) -> Self {
        Arc::get_mut(&mut self.runtime)
            .expect("runtime is not shared before run")
            .tls13 = true;
        self
    }

    /// Replaces the default public roots with one deployment-owned PEM CA.
    /// Certificate, DNS, ECDHE and Finished verification remain mandatory.
    /// Call before run; the trust store cannot be changed by an RPC peer.
    pub fn with_upstream_ca(mut self, path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        use std::io::Read;
        use tlsn::webpki::{CertificateDer, ServerCertVerifier};
        let mut pem = Vec::new();
        std::fs::File::open(path)?
            .take((1 << 20) + 1)
            .read_to_end(&mut pem)?;
        if pem.len() > 1 << 20 {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "upstream CA file too large").into(),
            );
        }
        let cert = CertificateDer::from_pem_slice(&pem)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid upstream CA PEM"))?;
        let roots = RootCertStore { roots: vec![cert] };
        ServerCertVerifier::new(&roots).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid upstream CA certificate",
            )
        })?;
        Arc::get_mut(&mut self.runtime)
            .ok_or_else(|| io::Error::other("sidecar runtime already shared"))?
            .root_store = roots;
        Ok(self)
    }

    /// Serves concurrent local clients until the shutdown future resolves.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ServiceError> {
        tokio::pin!(shutdown);
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    let runtime = Arc::clone(&self.runtime);
                    connections.spawn(async move {
                        let _ = serve_connection(stream, runtime).await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok(())
    }
}

#[derive(Debug)]
struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Sidecar service startup or connection failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Unix socket or local connection I/O failed.
    #[error("sidecar service I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Framed local RPC failed.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The selected socket path is empty.
    #[error("sidecar socket path must not be empty")]
    InvalidSocketPath,
    /// The server refuses to unlink an existing filesystem entry.
    #[error("sidecar socket path already exists: {}", .0.display())]
    SocketPathExists(PathBuf),
    /// The socket directory is not private to the service account.
    #[error("sidecar socket directory must be a mode-0700 private directory: {}", .0.display())]
    InsecureSocketDirectory(PathBuf),
    /// The local connection owner identifier was exhausted.
    #[error("sidecar connection identifier exhausted")]
    OwnerExhausted,
    /// Internal session state was poisoned by a panic.
    #[error("sidecar session registry is unavailable")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;
    use tokenhive_sidecar_protocol::{
        FrameType, PROTOCOL_VERSION, RpcHello, RpcHelloAck, RpcStatus,
    };
    use tokio::sync::oneshot;

    #[derive(Debug)]
    struct FixedCredentialResolver {
        credential_id: &'static str,
        credential: Vec<u8>,
    }

    impl CredentialResolver for FixedCredentialResolver {
        fn resolve(&self, credential_id: &str) -> Option<Zeroizing<Vec<u8>>> {
            (credential_id == self.credential_id).then(|| Zeroizing::new(self.credential.clone()))
        }
    }

    async fn handshake(
        path: &Path,
        role: Role,
    ) -> (
        FrameReader<tokio::net::unix::OwnedReadHalf>,
        FrameWriter<tokio::net::unix::OwnedWriteHalf>,
    ) {
        let stream = UnixStream::connect(path).await.unwrap();
        let (read, write) = stream.into_split();
        let mut reader = FrameReader::new(read);
        let mut writer = FrameWriter::new(write);
        let payload = serde_json::to_vec(&RpcHello {
            protocol_version: PROTOCOL_VERSION,
            expected_role: role,
        })
        .unwrap();
        writer
            .write_frame(FrameType::SidecarHello, 0, 0, &payload)
            .await
            .unwrap();
        let frame = reader.read_frame().await.unwrap();
        let ack: RpcHelloAck = serde_json::from_slice(&frame.payload).unwrap();
        assert_eq!(ack.capabilities.role, role);
        (reader, writer)
    }

    fn acknowledged_upstream_pair(
        capacity: usize,
    ) -> (
        DeliveryTrackedStream,
        DuplexStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (engine, relay) = tokio::io::duplex(capacity);
        let delivery = Arc::new(DeliveryState::new());
        let tracked = DeliveryTrackedStream::new(engine, Arc::clone(&delivery));
        let (network, server) = tokio::io::duplex(capacity);
        let task = tokio::spawn(async move {
            let (mut relay_read, mut relay_write) = tokio::io::split(relay);
            let (mut network_read, mut network_write) = tokio::io::split(network);
            let delivery_out = Arc::clone(&delivery);
            let outgoing = async move {
                let mut buffer = vec![0u8; tokenhive_sidecar_protocol::MAX_DATA_FRAME_SIZE];
                loop {
                    let size = relay_read.read(&mut buffer).await?;
                    if size == 0 {
                        return network_write.shutdown().await;
                    }
                    let bytes = &buffer[..size];
                    delivery_out.record_sent(bytes)?;
                    network_write.write_all(bytes).await?;
                    let state = delivery_out
                        .inner
                        .lock()
                        .map_err(|_| delivery_io_error("test delivery state lock failed"))?;
                    let expected = state.expected.front().expect("recorded checkpoint");
                    let ack = DeliveryAck {
                        bytes: expected.bytes,
                        sha256: expected.sha256,
                    };
                    drop(state);
                    delivery_out.acknowledge(ack)?;
                }
            };
            let incoming = async move {
                tokio::io::copy(&mut network_read, &mut relay_write).await?;
                relay_write.shutdown().await
            };
            tokio::try_join!(outgoing, incoming).map(|_| ())
        });
        (tracked, server, task)
    }

    fn private_tempdir() -> tempfile::TempDir {
        let directory = tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    async fn command(
        reader: &mut FrameReader<tokio::net::unix::OwnedReadHalf>,
        writer: &mut FrameWriter<tokio::net::unix::OwnedWriteHalf>,
        session_id: u64,
        command: RpcCommand,
    ) -> RpcResult {
        let payload = serde_json::to_vec(&command).unwrap();
        writer
            .write_frame(FrameType::SidecarCommand, 0, session_id, &payload)
            .await
            .unwrap();
        let frame = reader.read_frame().await.unwrap();
        assert_eq!(frame.frame_type, FrameType::SidecarResult);
        serde_json::from_slice(&frame.payload).unwrap()
    }

    fn attachment_token(result: &RpcResult) -> String {
        let data = result.data.as_ref().unwrap();
        data.get("attachment_token")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn serves_hub_lifecycle_over_mode_0600_socket() {
        let directory = private_tempdir();
        let socket = directory.path().join("hub.sock");
        let server = SidecarServer::bind(&socket, Role::Hub).unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.run(async {
            let _ = shutdown_rx.await;
        }));

        let (mut reader, mut writer) = handshake(&socket, Role::Hub).await;
        let create = command(
            &mut reader,
            &mut writer,
            19,
            RpcCommand {
                request_id: 1,
                operation: Operation::CreateSession,
                params: json!({
                    "upstream_policy": {
                        "host": "api.example.com",
                        "port": 443,
                        "server_name": "api.example.com"
                    }
                }),
            },
        )
        .await;
        assert_eq!(create.status, RpcStatus::Ok);
        assert_eq!(
            create.data.as_ref().unwrap().get("state"),
            Some(&json!("created"))
        );
        assert_eq!(attachment_token(&create).len(), ATTACHMENT_TOKEN_SIZE * 2);

        let close = command(
            &mut reader,
            &mut writer,
            19,
            RpcCommand {
                request_id: 2,
                operation: Operation::CloseSession,
                params: json!({}),
            },
        )
        .await;
        assert_eq!(close.status, RpcStatus::Ok);

        drop(reader);
        drop(writer);
        shutdown_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn provider_rejects_api_key_and_requires_attachments() {
        let directory = private_tempdir();
        let socket = directory.path().join("provider.sock");
        let server = SidecarServer::bind(&socket, Role::Provider).unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(server.run(async {
            let _ = shutdown_rx.await;
        }));
        let (mut reader, mut writer) = handshake(&socket, Role::Provider).await;

        let rejected = command(
            &mut reader,
            &mut writer,
            7,
            RpcCommand {
                request_id: 1,
                operation: Operation::BindCredential,
                params: json!({
                    "credential_id": "provider-ref",
                    "api_key": "must-not-be-accepted",
                    "upstream_policy": {
                        "host": "api.example.com",
                        "port": 443,
                        "server_name": "api.example.com"
                    }
                }),
            },
        )
        .await;
        assert_eq!(rejected.status, RpcStatus::Error);
        assert_eq!(rejected.error_code.as_deref(), Some("invalid_params"));

        let bound = command(
            &mut reader,
            &mut writer,
            7,
            RpcCommand {
                request_id: 2,
                operation: Operation::BindCredential,
                params: json!({
                    "credential_id": "provider-ref",
                    "upstream_policy": {
                        "host": "api.example.com",
                        "port": 443,
                        "server_name": "api.example.com"
                    }
                }),
            },
        )
        .await;
        assert_eq!(bound.status, RpcStatus::Ok);

        let handshake_result = command(
            &mut reader,
            &mut writer,
            7,
            RpcCommand {
                request_id: 3,
                operation: Operation::RunHandshake,
                params: json!({}),
            },
        )
        .await;
        assert_eq!(handshake_result.status, RpcStatus::Error);
        assert_eq!(
            handshake_result.error_code.as_deref(),
            Some("missing_attachment")
        );

        drop(reader);
        drop(writer);
        shutdown_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn refuses_existing_socket_path() {
        let directory = private_tempdir();
        let socket = directory.path().join("sidecar.sock");
        std::fs::write(&socket, b"do not replace").unwrap();
        assert!(matches!(
            SidecarServer::bind(&socket, Role::Hub),
            Err(ServiceError::SocketPathExists(_))
        ));
        assert_eq!(std::fs::read(&socket).unwrap(), b"do not replace");
    }

    #[test]
    fn refuses_socket_in_shared_directory() {
        let directory = tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = directory.path().join("sidecar.sock");
        assert!(matches!(
            SidecarServer::bind(&socket, Role::Hub),
            Err(ServiceError::InsecureSocketDirectory(_))
        ));
        assert!(!socket.exists());
    }

    #[test]
    fn refuses_symlink_socket_directory() {
        let target = private_tempdir();
        let container = private_tempdir();
        let linked_directory = container.path().join("runtime");
        std::os::unix::fs::symlink(target.path(), &linked_directory).unwrap();
        let socket = linked_directory.join("sidecar.sock");
        assert!(matches!(
            SidecarServer::bind(&socket, Role::Hub),
            Err(ServiceError::InsecureSocketDirectory(_))
        ));
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn attachment_token_gates_full_duplex_channel() {
        let runtime = Runtime::new(Role::Hub);
        let owner = runtime.allocate_owner().unwrap();
        let created = runtime.create_session(
            owner,
            91,
            1,
            json!({
                "upstream_policy": {
                    "host": "api.example.com",
                    "port": 443,
                    "server_name": "api.example.com"
                }
            }),
        );
        let token = attachment_token(&created);
        let rejected = runtime.attach_channel(
            91,
            2,
            Operation::AttachMpcChannel,
            json!({"attachment_token": "00".repeat(ATTACHMENT_TOKEN_SIZE)}),
        );
        assert_eq!(
            rejected.unwrap_err().error_code.as_deref(),
            Some("attachment_rejected")
        );

        let rpc_channel = runtime
            .attach_channel(
                91,
                3,
                Operation::AttachMpcChannel,
                json!({"attachment_token": token}),
            )
            .unwrap();
        let mut engine_channel = runtime
            .registry
            .lock()
            .unwrap()
            .sessions
            .get_mut(&91)
            .unwrap()
            .mpc_channel
            .take()
            .unwrap();

        let (client_io, server_io) = tokio::io::duplex(1 << 18);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let mut client_reader = FrameReader::new(client_read);
        let mut client_writer = FrameWriter::new(client_write);
        let pump = tokio::spawn(pump_attachment(
            FrameReader::new(server_read),
            FrameWriter::new(server_write),
            rpc_channel,
            91,
        ));

        client_writer
            .write_frame(FrameType::SidecarStream, 0, 91, b"mpc request")
            .await
            .unwrap();
        let mut request = [0u8; 11];
        engine_channel.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"mpc request");

        engine_channel.write_all(b"mpc response").await.unwrap();
        engine_channel.shutdown().await.unwrap();
        let response = client_reader.read_frame().await.unwrap();
        assert_eq!(response.frame_type, FrameType::SidecarStream);
        assert_eq!(response.payload, b"mpc response");
        let response_end = client_reader.read_frame().await.unwrap();
        assert_eq!(response_end.frame_type, FrameType::SidecarStreamEnd);

        client_writer
            .write_frame(FrameType::SidecarStreamEnd, 0, 91, &[])
            .await
            .unwrap();
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upstream_flush_waits_for_matching_delivery_ack() {
        let (engine_channel, rpc_channel) = tokio::io::duplex(1 << 18);
        let delivery = Arc::new(DeliveryState::new());
        let mut engine_channel = DeliveryTrackedStream::new(engine_channel, Arc::clone(&delivery));
        let attachment = AttachedChannel {
            channel: rpc_channel,
            delivery: Some(delivery),
        };

        let (client_io, server_io) = tokio::io::duplex(1 << 18);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let mut client_reader = FrameReader::new(client_read);
        let mut client_writer = FrameWriter::new(client_write);
        let pump = tokio::spawn(pump_attachment(
            FrameReader::new(server_read),
            FrameWriter::new(server_write),
            attachment,
            93,
        ));

        let ciphertext = b"tls request ciphertext";
        let mut flush = tokio::spawn(async move {
            engine_channel.write_all(ciphertext).await?;
            engine_channel.flush().await
        });
        let frame = client_reader.read_frame().await.unwrap();
        assert_eq!(frame.frame_type, FrameType::SidecarStream);
        assert_eq!(frame.payload, ciphertext);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut flush)
                .await
                .is_err(),
            "upstream flush completed before delivery ACK"
        );

        let ack = DeliveryAck {
            bytes: ciphertext.len() as u64,
            sha256: sha2::Sha256::digest(ciphertext).into(),
        }
        .encode()
        .unwrap();
        client_writer
            .write_frame(FrameType::DeliveryAck, 0, 93, &ack)
            .await
            .unwrap();
        flush.await.unwrap().unwrap();
        let end = client_reader.read_frame().await.unwrap();
        assert_eq!(end.frame_type, FrameType::SidecarStreamEnd);
        client_writer
            .write_frame(FrameType::SidecarStreamEnd, 0, 93, &[])
            .await
            .unwrap();
        pump.await.unwrap().unwrap();
    }

    #[test]
    fn delivery_state_rejects_wrong_prefix_digest() {
        let delivery = DeliveryState::new();
        delivery.record_sent(b"ciphertext").unwrap();
        assert!(
            delivery
                .acknowledge(DeliveryAck {
                    bytes: 10,
                    sha256: [0x55; 32],
                })
                .is_err()
        );
        assert!(delivery.inner.lock().unwrap().failed);
    }

    #[test]
    fn hub_handshake_requires_response_attachment_without_consuming_mpc() {
        let runtime = Runtime::new(Role::Hub);
        let owner = runtime.allocate_owner().unwrap();
        assert_eq!(
            runtime
                .create_session(
                    owner,
                    92,
                    1,
                    json!({
                        "upstream_policy": {
                            "host": "api.example.com",
                            "port": 443,
                            "server_name": "api.example.com"
                        }
                    }),
                )
                .status,
            RpcStatus::Ok
        );
        let (mpc_channel, _peer) = tokio::io::duplex(1024);
        runtime
            .registry
            .lock()
            .unwrap()
            .sessions
            .get_mut(&92)
            .unwrap()
            .mpc_channel = Some(mpc_channel);

        let result = runtime.take_handshake_inputs(owner, 92, 2);
        let Err(error) = result else {
            panic!("handshake unexpectedly accepted without response attachment")
        };
        assert_eq!(error.error_code.as_deref(), Some("missing_attachment"));
        assert!(
            runtime.registry.lock().unwrap().sessions[&92]
                .mpc_channel
                .is_some()
        );
    }

    #[tokio::test]
    async fn selective_request_dispatch_validates_canonical_bytes_before_engine() {
        let runtime = Runtime::new(Role::Hub);
        let owner = runtime.allocate_owner().unwrap();
        assert_eq!(
            runtime
                .create_session(
                    owner,
                    117,
                    1,
                    json!({
                        "upstream_policy": {
                            "host": "api.openai.com",
                            "port": 443,
                            "server_name": "api.openai.com"
                        }
                    }),
                )
                .status,
            RpcStatus::Ok
        );
        let vector: Value = serde_json::from_str(include_str!(
            "../../../../testdata/canonical-request-v1.json"
        ))
        .unwrap();
        let encoded = vector["canonical_request_hex"].as_str().unwrap();
        let request: Vec<u8> = encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let params = json!({
            "task_id": "task-117",
            "adapter": vector["adapter"],
            "credential_length": vector["credential_length"],
            "public_request_hash": vector["public_request_hash"],
        });

        let valid = runtime
            .dispatch(
                owner,
                117,
                RpcCommand {
                    request_id: 2,
                    operation: Operation::EncryptRequest,
                    params: params.clone(),
                },
                Some(request.clone()),
            )
            .await;
        assert_eq!(valid.error_code.as_deref(), Some("invalid_state"));

        let mut modified = request;
        *modified.last_mut().unwrap() ^= 1;
        let rejected = runtime
            .dispatch(
                owner,
                117,
                RpcCommand {
                    request_id: 3,
                    operation: Operation::EncryptRequest,
                    params,
                },
                Some(modified),
            )
            .await;
        assert_eq!(
            rejected.error_code.as_deref(),
            Some("invalid_canonical_request")
        );
    }

    #[tokio::test]
    async fn rejects_provider_injected_server_record_command() {
        let runtime = Runtime::new(Role::Hub);
        let owner = runtime.allocate_owner().unwrap();
        assert_eq!(
            runtime
                .create_session(
                    owner,
                    118,
                    1,
                    json!({
                        "upstream_policy": {
                            "host": "api.openai.com",
                            "port": 443,
                            "server_name": "api.openai.com"
                        }
                    }),
                )
                .status,
            RpcStatus::Ok
        );

        let rejected = runtime
            .dispatch(
                owner,
                118,
                RpcCommand {
                    request_id: 2,
                    operation: Operation::FeedServerRecords,
                    params: json!({}),
                },
                Some(vec![0x17, 0x03, 0x03, 0, 1, 0]),
            )
            .await;
        assert_eq!(rejected.status, RpcStatus::Error);
        assert_eq!(rejected.error_code.as_deref(), Some("not_implemented"));
        assert!(matches!(
            runtime.registry.lock().unwrap().sessions[&118].engine,
            EngineState::Allocated
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "expensive two-party sidecar MPC integration test"]
    async fn attached_channels_run_real_selective_mpc_tls_request() {
        use tlsn::webpki::CertificateDer;
        use tlsn_server_fixture::bind;
        use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

        let root_store = RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        };
        let large_record_test = std::env::var_os("TOKENHIVE_MPC_TEST_PUBLIC_BODY").is_some();
        let benchmark_capacity = std::env::var("TOKENHIVE_MPC_BENCH_CAPACITY_BYTES")
            .ok()
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("benchmark capacity must be an integer")
            });
        let max_sent_data =
            benchmark_capacity.unwrap_or(if large_record_test { 18 << 10 } else { 1 << 12 });
        assert!(
            max_sent_data <= canonical::MAX_REQUEST_LENGTH,
            "benchmark capacity exceeds the largest protocol-v1 profile"
        );
        let test_limits = MpcLimits {
            max_sent_data,
            // TLSNotary counts the three client-direction handshake records in
            // addition to the fragmented application request.
            max_sent_records: max_sent_data.div_ceil(TLS_PLAINTEXT_FRAGMENT_SIZE) + 3,
            max_recv_data: 1 << 14,
            max_recv_records_online: 6,
        };
        let hub = Runtime {
            role: Role::Hub,
            tls13: false,
            root_store: root_store.clone(),
            limits: test_limits.clone(),
            credential_resolver: Arc::new(EmptyCredentialResolver),
            registry: Mutex::new(Registry::default()),
        };
        let provider = Runtime {
            role: Role::Provider,
            tls13: false,
            root_store,
            limits: test_limits,
            credential_resolver: Arc::new(FixedCredentialResolver {
                credential_id: "fixture-credential",
                credential: vec![b'k'; 48],
            }),
            registry: Mutex::new(Registry::default()),
        };
        let hub_owner = hub.allocate_owner().unwrap();
        let provider_owner = provider.allocate_owner().unwrap();
        let policy = json!({
            "upstream_policy": {
                "host": SERVER_DOMAIN,
                "port": 443,
                "server_name": SERVER_DOMAIN
            }
        });
        assert_eq!(
            hub.create_session(hub_owner, 301, 1, policy.clone()).status,
            RpcStatus::Ok
        );
        assert_eq!(
            provider
                .bind_credential(
                    provider_owner,
                    301,
                    1,
                    json!({
                        "credential_id": "fixture-credential",
                        "upstream_policy": policy["upstream_policy"].clone(),
                    }),
                )
                .status,
            RpcStatus::Ok
        );

        let (provider_mpc, hub_mpc) = tokio::io::duplex(2 << 23);
        let (upstream, server, upstream_relay) = acknowledged_upstream_pair(2 << 16);
        let (hub_response, mut response_client) = tokio::io::duplex(2 << 16);
        {
            let mut registry = hub.registry.lock().unwrap();
            let session = registry.sessions.get_mut(&301).unwrap();
            session.mpc_channel = Some(hub_mpc);
            session.response_channel = Some(hub_response);
        }
        {
            let mut registry = provider.registry.lock().unwrap();
            let session = registry.sessions.get_mut(&301).unwrap();
            session.mpc_channel = Some(provider_mpc);
            session.upstream_channel = Some(upstream);
        }
        let mut server_task = tokio::spawn(bind(server.compat()));

        let handshake_started = std::time::Instant::now();
        let (hub_result, provider_result) = tokio::join!(
            hub.run_handshake(hub_owner, 301, 2, json!({})),
            provider.run_handshake(provider_owner, 301, 2, json!({}))
        );
        let handshake_elapsed = handshake_started.elapsed();
        assert_eq!(
            provider_result.status,
            RpcStatus::Ok,
            "Provider handshake result: {provider_result:?}; Hub result: {hub_result:?}"
        );
        assert_eq!(
            provider_result.data.as_ref().unwrap()["state"],
            "handshake_running"
        );
        assert_eq!(hub_result.status, RpcStatus::Ok);
        assert_eq!(hub_result.data.as_ref().unwrap()["state"], "ready");
        assert_eq!(
            hub_result.data.as_ref().unwrap()["upstream_authenticated"],
            true
        );
        if std::env::var_os("TOKENHIVE_MPC_BENCH_PAD_BYTES").is_some() {
            eprintln!(
                "tokenhive_mpc_benchmark_phase phase=handshake_complete handshake_ms={}",
                handshake_elapsed.as_millis()
            );
        }
        {
            let hub_registry = hub.registry.lock().unwrap();
            let EngineState::HubReady(engine) = &hub_registry.sessions[&301].engine else {
                panic!("Hub did not retain the authenticated engine")
            };
            assert!(!engine.response_task.0.is_finished());
        }

        let benchmark_pad = std::env::var("TOKENHIVE_MPC_BENCH_PAD_BYTES")
            .ok()
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("benchmark padding must be an integer")
            })
            .unwrap_or_else(|| if large_record_test { 16 << 10 } else { 0 });
        let body = if benchmark_pad == 0 {
            br#"{"messages":[{"content":"ping","role":"user"}],"model":"fixture"}"#.to_vec()
        } else {
            format!(
                r#"{{"input":"{}","messages":[{{"content":"ping","role":"user"}}],"model":"fixture"}}"#,
                "x".repeat(benchmark_pad)
            )
            .into_bytes()
        };
        let credential_length = 48;
        let mut request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {SERVER_DOMAIN}\r\nAuthorization: Bearer "
        )
        .into_bytes();
        request.extend(std::iter::repeat_n(0, credential_length));
        request.extend_from_slice(
            format!(
                "\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        request.extend_from_slice(&body);
        assert!(
            request.len() <= canonical::MAX_REQUEST_LENGTH,
            "benchmark request exceeds the negotiated MPC capacity"
        );
        let request_hash: [u8; 32] = sha2::Sha256::digest(&request).into();
        let request_plaintext_bytes = request.len() as u64;
        let request_records = request.len().div_ceil(TLS_PLAINTEXT_FRAGMENT_SIZE) as u64;
        let expected_request_wire_bytes =
            request_plaintext_bytes + request_records * TLS12_AES_GCM_RECORD_OVERHEAD;
        let params = json!({
            "task_id": "task-301",
            "adapter": "openai_chat_completions_v1",
            "credential_length": credential_length,
            "public_request_hash": encode_hash(&request_hash),
        });
        let hub_prepared = hub
            .dispatch(
                hub_owner,
                301,
                RpcCommand {
                    request_id: 3,
                    operation: Operation::EncryptRequest,
                    params: params.clone(),
                },
                Some(request.clone()),
            )
            .await;
        assert_eq!(hub_prepared.status, RpcStatus::Ok);
        assert_eq!(
            hub_prepared.data.as_ref().unwrap()["state"],
            "request_prepared"
        );
        let request_started = std::time::Instant::now();
        let provider_encrypted = provider
            .dispatch(
                provider_owner,
                301,
                RpcCommand {
                    request_id: 3,
                    operation: Operation::ContributeRequestEncryption,
                    params,
                },
                Some(request),
            )
            .await;
        let request_elapsed = request_started.elapsed();
        assert_eq!(
            provider_encrypted.status,
            RpcStatus::Ok,
            "Provider result: {provider_encrypted:?}"
        );
        assert_eq!(
            provider_encrypted.data.as_ref().unwrap()["state"],
            "request_delivered"
        );
        let delivery = &provider_encrypted.data.as_ref().unwrap()["upstream_delivery"];
        let cumulative_bytes = delivery["cumulative_bytes"].as_u64().unwrap();
        let request_bytes = delivery["request_bytes"].as_u64().unwrap();
        assert_eq!(request_bytes, expected_request_wire_bytes);
        assert!(cumulative_bytes >= request_bytes);
        assert_eq!(delivery["sha256"].as_str().unwrap().len(), 64);
        if benchmark_pad != 0 {
            eprintln!(
                "tokenhive_mpc_benchmark capacity_bytes={} body_bytes={} request_plaintext_bytes={} request_records={} handshake_ms={} request_delivery_ms={}",
                max_sent_data,
                body.len(),
                request_plaintext_bytes,
                request_records,
                handshake_elapsed.as_millis(),
                request_elapsed.as_millis(),
            );
        }
        tokio::time::timeout(Duration::from_secs(30), &mut server_task)
            .await
            .expect("TLS fixture did not receive the selective request")
            .expect("TLS fixture task panicked")
            .expect("TLS fixture rejected the selective request");

        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(30),
            response_client.read_to_end(&mut response),
        )
        .await
        .expect("Hub response channel did not close")
        .expect("Hub response channel failed");
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(response.windows(4).any(|window| window == b"\r\n\r\n"));

        let _ = hub.remove_session(hub_owner, 301, 4).await;
        let _ = provider.remove_session(provider_owner, 301, 4).await;
        upstream_relay.await.unwrap().unwrap();
    }
}
