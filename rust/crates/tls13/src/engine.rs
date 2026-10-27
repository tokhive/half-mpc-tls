use crate::{
    Result, fail,
    mpc::Party,
    record::{self, Traffic, WarmPrefix},
    schedule::{self, Secret},
    wire::{self, Handshakes},
};
use futures::future::poll_fn;
use mpz_common::{Context, Executor, io::Io, mux::Mux};
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use std::ops::Range;
use subtle::ConstantTimeEq;
use tlsn_core::webpki::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Per-session identity and byte limits, matched by both participants.
pub struct Policy {
    /// DNS identity verified against the upstream certificate.
    pub server_name: String,
    /// Maximum canonical request bytes, including the zero credential slot.
    pub max_request: usize,
    /// Maximum incoming encrypted bytes, including post-handshake messages.
    pub max_response: usize,
}
impl Policy {
    fn validate(&self) -> Result<()> {
        if self.max_request == 0
            || self.max_request > 5 << 20
            || self.max_response == 0
            || self.max_response > 16 << 20
        {
            return Err(fail("TLS 1.3 capacity limit"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
enum Control {
    Init(Policy),
    Hello {
        server_key: Vec<u8>,
        hash: [u8; 32],
    },
    Verified {
        hash: [u8; 32],
    },
    Ready,
    Plan {
        hash: [u8; 32],
        start: usize,
        end: usize,
        len: usize,
    },
    Switched,
    Delivered,
}
#[derive(Serialize, Deserialize)]
enum WireCommand {
    Write(Vec<u8>),
    Read,
}
#[derive(Serialize, Deserialize)]
enum WireReply {
    Ack,
    Record(Vec<u8>),
}

struct MuxHandle(tlsn_mux::Handle);
impl Mux for MuxHandle {
    fn open(&self, id: &[u8]) -> std::io::Result<Io> {
        Ok(Io::from_io(
            self.0.new_stream(id).map_err(std::io::Error::other)?,
        ))
    }
}
struct Network {
    task: tokio::task::JoinHandle<()>,
    _executor: Executor,
}
impl Drop for Network {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Wire(Io);
impl Wire {
    async fn write(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.0.send(WireCommand::Write(bytes)).await?;
        if !matches!(self.0.expect_next::<WireReply>().await?, WireReply::Ack) {
            return Err(fail("missing upstream delivery ACK"));
        }
        Ok(())
    }
    async fn read(&mut self) -> Result<Vec<u8>> {
        self.0.send(WireCommand::Read).await?;
        match self.0.expect_next::<WireReply>().await? {
            WireReply::Record(record) => Ok(record),
            _ => Err(fail("unexpected upstream relay reply")),
        }
    }
}
async fn relay<T: AsyncRead + AsyncWrite + Unpin>(mut wire: Wire, mut upstream: T) -> Result<()> {
    loop {
        match wire.0.expect_next::<WireCommand>().await? {
            WireCommand::Write(data) => {
                if data.is_empty() || data.len() > 512 << 10 {
                    return Err(fail("relay batch length"));
                }
                let mut offset = 0;
                while offset < data.len() {
                    if data.len() - offset < 5 {
                        return Err(fail("truncated relay record"));
                    }
                    let len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
                    if len == 0 || len > record::MAX_CIPHER || offset + 5 + len > data.len() {
                        return Err(fail("relay record length"));
                    }
                    offset += 5 + len;
                }
                upstream.write_all(&data).await?;
                upstream.flush().await?;
                wire.0.send(WireReply::Ack).await?;
            }
            WireCommand::Read => {
                let mut header = [0u8; 5];
                upstream.read_exact(&mut header).await?;
                let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                if len == 0 || len > record::MAX_CIPHER {
                    return Err(fail("upstream record length"));
                }
                let mut data = vec![0; 5 + len];
                data[..5].copy_from_slice(&header);
                upstream.read_exact(&mut data[5..]).await?;
                wire.0.send(WireReply::Record(data)).await?;
            }
        }
    }
}
fn network(peer: DuplexStream) -> Result<(Network, Context, Wire)> {
    let mut config = tlsn_mux::Config::default();
    config
        .set_max_num_streams(4096)
        .set_keep_alive(true)
        .set_close_sync(true);
    let mut conn = tlsn_mux::Connection::new(peer.compat(), config);
    let handle = conn.handle()?;
    let wire = Wire(Io::from_io(handle.new_stream(b"tokenhive-tls13-wire-v1")?));
    let executor = Executor::builder()
        .num_threads(
            std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(2),
        )
        .build(MuxHandle(handle));
    let ctx = executor.new_context()?;
    let task = tokio::spawn(async move {
        let _ = poll_fn(|cx| conn.poll(cx)).await;
    });
    Ok((
        Network {
            task,
            _executor: executor,
        },
        ctx,
        wire,
    ))
}
async fn send(p: &mut Party, m: Control) -> Result<()> {
    p.ctx.io_mut().send(m).await?;
    Ok(())
}
async fn recv(p: &mut Party) -> Result<Control> {
    Ok(p.ctx.io_mut().expect_next::<Control>().await?)
}
fn required<T>(value: Option<T>) -> Result<T> {
    value.ok_or_else(|| fail("Hub output missing"))
}

/// One-shot Hub session. Drop on every error; never reuse across requests.
pub struct Hub {
    party: Party,
    old: WarmPrefix,
    next: Secret,
    wire: Wire,
    server: Traffic,
    client: Option<Traffic>,
    output: DuplexStream,
    _network: Network,
    policy: Policy,
    used: bool,
}
/// One-shot Provider session, retaining the upstream relay until dropped.
pub struct Provider {
    party: Party,
    old: WarmPrefix,
    next: Secret,
    _network: Network,
    relay: tokio::task::JoinHandle<()>,
    policy: Policy,
    used: bool,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.relay.abort();
    }
}

/// Establish TLS 1.3 using real two-party ECDHE/HKDF and verify the upstream.
///
/// Run concurrently with [`provider_handshake`]. The caller must authenticate
/// the MPC peer channel and impose a timeout. The response output must be
/// drained concurrently when it exceeds the duplex buffer.
pub async fn hub_handshake(
    peer: DuplexStream,
    output: DuplexStream,
    roots: RootCertStore,
    policy: Policy,
) -> Result<Hub> {
    policy.validate()?;
    let (network, ctx, mut wire) = network(peer)?;
    let mut party = Party::new(false, ctx).await?;
    send(&mut party, Control::Init(policy.clone())).await?;
    let public_key = party.public_key().await?;
    let random = rand::random();
    let session = rand::random();
    let ch = wire::client_hello(&policy.server_name, &public_key, random, session)?;
    let mut transcript = ch.clone();
    wire.write(wire::plaintext_record(&ch)?).await?;
    let mut messages = Handshakes::default();
    let mut hello_records = 0;
    let sh = loop {
        hello_records += 1;
        if hello_records > 128 {
            return Err(fail("ServerHello record limit"));
        }
        let record = wire.read().await?;
        if record.len() < 5 || record[0] != 22 || record[1..3] != [3, 3] {
            return Err(fail("expected plaintext ServerHello"));
        }
        messages.feed(&record[5..])?;
        if let Some(sh) = messages.next()? {
            if !messages.empty() {
                return Err(fail("unexpected plaintext handshake after ServerHello"));
            }
            break sh;
        }
    };
    let server_key = wire::server_hello(&sh, &session)?;
    transcript.extend_from_slice(&sh);
    let hello_hash = wire::hash(&transcript);
    send(
        &mut party,
        Control::Hello {
            server_key: server_key.clone(),
            hash: hello_hash,
        },
    )
    .await?;
    party.exchange(&server_key).await?;
    let pms = party.pms;
    let hs = schedule::handshake(party.vm.vm(), pms, &hello_hash)?;
    let server_secret = Zeroizing::new(required(party.reveal(hs.server).await?)?);
    let mut server_hs = Traffic::new(*server_secret)?;
    let mut step = 0;
    let mut cert = None;
    let mut ccs = 0;
    let mut handshake_records = 0;
    loop {
        let record = wire.read().await?;
        handshake_records += 1;
        if handshake_records > 128 {
            return Err(fail("handshake record limit"));
        }
        if record == [20, 3, 3, 0, 1, 1] {
            ccs += 1;
            if ccs > 2 {
                return Err(fail("excess compatibility CCS"));
            }
            continue;
        }
        let (kind, plain) = server_hs.open(&record)?;
        if kind != 22 {
            return Err(fail("unexpected encrypted handshake content"));
        }
        messages.feed(&plain)?;
        let mut finished = false;
        while let Some(message) = messages.next()? {
            match step {
                0 => wire::encrypted_extensions(&message)?,
                1 => cert = Some(wire::certificate(&message, &roots, &policy.server_name)?),
                2 => wire::certificate_verify(
                    &message,
                    cert.as_ref().ok_or_else(|| fail("missing certificate"))?,
                    &wire::hash(&transcript),
                )?,
                3 => {
                    let verify = wire::body(&message, 20)?;
                    let key = Zeroizing::new(schedule::local_expand(
                        &server_secret,
                        b"finished",
                        &[],
                        32,
                    )?);
                    let expected =
                        Zeroizing::new(schedule::local_hmac(&key, &wire::hash(&transcript)));
                    if verify.len() != 32 || !bool::from(verify.ct_eq(expected.as_slice())) {
                        return Err(fail("server Finished mismatch"));
                    }
                    finished = true;
                }
                _ => return Err(fail("unexpected handshake after Finished")),
            }
            transcript.extend_from_slice(&message);
            step += 1;
        }
        if finished {
            if !messages.empty() {
                return Err(fail("partial handshake after Finished"));
            }
            break;
        }
    }
    let finished_hash = wire::hash(&transcript);
    send(
        &mut party,
        Control::Verified {
            hash: finished_hash,
        },
    )
    .await?;
    let (old, next, server) = application(&mut party, hs.master, hs.client, &finished_hash).await?;
    let client_hs = Zeroizing::new(required(party.reveal(hs.client).await?)?);
    let key = Zeroizing::new(schedule::local_expand(&client_hs, b"finished", &[], 32)?);
    let finished = wire::handshake(20, &schedule::local_hmac(&key, &finished_hash))?;
    wire.write(Traffic::new(*client_hs)?.seal(22, &finished)?)
        .await?;
    send(&mut party, Control::Ready).await?;
    if !matches!(recv(&mut party).await?, Control::Ready) {
        return Err(fail("peer handshake readiness mismatch"));
    }
    Ok(Hub {
        party,
        old,
        next,
        wire,
        server: Traffic::new(required(server)?)?,
        client: None,
        output,
        _network: network,
        policy,
        used: false,
    })
}

async fn application(
    party: &mut Party,
    master: Secret,
    _client_hs: Secret,
    hash: &[u8; 32],
) -> Result<(WarmPrefix, Secret, Option<[u8; 32]>)> {
    let vm = party.vm.vm();
    let old = schedule::expand(vm, master, b"c ap traffic", hash)?;
    let server = schedule::expand(vm, master, b"s ap traffic", hash)?;
    let next = schedule::expand(vm, old, b"traffic upd", &[])?;
    let warm = WarmPrefix::new(vm, old)?;
    // Application response secret is decoded only after Hub verifies the handshake.
    let server = party.reveal(server).await?;
    Ok((warm, next, server))
}

/// Participate in the handshake and relay upstream records.
///
/// `upstream.flush()` must confirm actual network delivery if the transport
/// forwards bytes through another process. It is the KeyUpdate release barrier.
/// The caller must authenticate the MPC peer and impose a timeout.
pub async fn provider_handshake<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    peer: DuplexStream,
    upstream: T,
    policy: Policy,
) -> Result<Provider> {
    policy.validate()?;
    let (network, ctx, wire) = network(peer)?;
    let relay = tokio::spawn(async move {
        let _ = relay(wire, upstream).await;
    });
    // Abort on any handshake failure as well as when the returned engine is dropped.
    let mut guard = RelayGuard(Some(relay));
    let mut party = Party::new(true, ctx).await?;
    match recv(&mut party).await? {
        Control::Init(expected) if expected == policy => {}
        _ => return Err(fail("peer policy mismatch")),
    }
    party.public_key().await?;
    let (server_key, hash) = match recv(&mut party).await? {
        Control::Hello { server_key, hash } => (server_key, hash),
        _ => return Err(fail("expected ServerHello binding")),
    };
    party.exchange(&server_key).await?;
    let pms = party.pms;
    let hs = schedule::handshake(party.vm.vm(), pms, &hash)?;
    party.reveal(hs.server).await?;
    let hash = match recv(&mut party).await? {
        Control::Verified { hash } => hash,
        _ => return Err(fail("expected verified handshake")),
    };
    let (old, next, _) = application(&mut party, hs.master, hs.client, &hash).await?;
    party.reveal(hs.client).await?;
    if !matches!(recv(&mut party).await?, Control::Ready) {
        return Err(fail("expected client Finished delivery"));
    }
    send(&mut party, Control::Ready).await?;
    Ok(Provider {
        party,
        old,
        next,
        _network: network,
        relay: guard.0.take().unwrap(),
        policy,
        used: false,
    })
}
struct RelayGuard(Option<tokio::task::JoinHandle<()>>);
impl Drop for RelayGuard {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

fn plan(request: &[u8], span: &Range<usize>, policy: &Policy) -> Result<usize> {
    if request.len() > policy.max_request
        || span.start >= span.end
        || span.end > request.len().saturating_sub(2)
        || span.end > record::PREFIX_CAPACITY - 3
        || request[span.end..span.end + 2] != *b"\r\n"
        || request[span.clone()].iter().any(|b| *b != 0)
    {
        return Err(fail("invalid one-shot request plan"));
    }
    Ok(span.end + 2)
}
impl Hub {
    /// Send one request with a zero-filled credential range.
    /// Both parties must independently validate the canonical HTTP template;
    /// this engine enforces matching bytes, bounds, the slot and one-shot use.
    pub async fn request(&mut self, request: &[u8], span: Range<usize>) -> Result<()> {
        if std::mem::replace(&mut self.used, true) {
            return Err(fail("session already used"));
        }
        let cut = plan(request, &span, &self.policy)?;
        send(
            &mut self.party,
            Control::Plan {
                hash: wire::hash(request),
                start: span.start,
                end: span.end,
                len: request.len(),
            },
        )
        .await?;
        let (prefix, update) = required(
            self.old
                .encrypt(&mut self.party, &request[..cut], None, span)
                .await?,
        )?;
        self.wire.write(prefix).await?;
        self.wire.write(update).await?;
        // Both writes have received actual upstream-delivery acknowledgements.
        send(&mut self.party, Control::Switched).await?;
        let secret = required(self.party.reveal(self.next).await?)?;
        let mut client = Traffic::new(secret)?;
        let mut batch = Vec::with_capacity(512 << 10);
        for chunk in request[cut..].chunks(record::MAX_PLAIN) {
            let record = client.seal(23, chunk)?;
            if batch.len() + record.len() > 512 << 10 {
                self.wire.write(std::mem::take(&mut batch)).await?;
            }
            batch.extend_from_slice(&record);
        }
        if !batch.is_empty() {
            self.wire.write(batch).await?;
        }
        self.client = Some(client);
        send(&mut self.party, Control::Delivered).await?;
        if !matches!(recv(&mut self.party).await?, Control::Delivered) {
            return Err(fail("missing peer completion"));
        }
        Ok(())
    }
    /// Authenticate and forward response bytes, processing tickets and KeyUpdate.
    /// EOF without close_notify and all record failures are returned as errors.
    pub async fn response(&mut self) -> Result<()> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| fail("request not delivered"))?;
        let mut post = Handshakes::default();
        let mut bytes = 0usize;
        let mut updates = 0usize;
        loop {
            let record = self.wire.read().await?;
            bytes = bytes
                .checked_add(record.len())
                .ok_or_else(|| fail("response overflow"))?;
            if bytes > self.policy.max_response {
                return Err(fail("response capacity exceeded"));
            }
            let (kind, plain) = self.server.open(&record)?;
            match kind {
                23 => {
                    if !post.empty() {
                        return Err(fail("application record interrupted handshake"));
                    }
                    self.output.write_all(&plain).await?;
                }
                21 => {
                    if plain.as_slice() != [1, 0] || !post.empty() {
                        return Err(fail("upstream TLS alert"));
                    }
                    self.output.shutdown().await?;
                    return Ok(());
                }
                22 => {
                    post.feed(&plain)?;
                    while let Some(message) = post.next()? {
                        match message[0] {
                            4 => {
                                let mut r = wire::Reader::new(wire::body(&message, 4)?);
                                r.take(8)?;
                                r.vector8()?;
                                if r.vector16()?.is_empty() {
                                    return Err(fail("empty session ticket"));
                                }
                                r.vector16()?;
                                r.end()?;
                            }
                            24 => {
                                if !post.empty() {
                                    return Err(fail("KeyUpdate must end a TLS record"));
                                }
                                let body = wire::body(&message, 24)?;
                                if body.len() != 1 || body[0] > 1 {
                                    return Err(fail("invalid KeyUpdate"));
                                }
                                updates += 1;
                                if updates > 32 {
                                    return Err(fail("too many KeyUpdates"));
                                }
                                self.server.update()?;
                                if body[0] == 1 {
                                    self.wire.write(client.seal(22, &[24, 0, 0, 1, 0])?).await?;
                                    client.update()?;
                                }
                            }
                            _ => return Err(fail("unsupported post-handshake message")),
                        }
                    }
                }
                _ => return Err(fail("unexpected TLS content type")),
            }
        }
    }
}
impl Provider {
    /// Contribute only the credential to the canonical request agreed with Hub.
    /// Run concurrently with [`Hub::request`]; drop the session on any failure.
    pub async fn request(
        &mut self,
        request: &[u8],
        span: Range<usize>,
        credential: &[u8],
    ) -> Result<()> {
        if std::mem::replace(&mut self.used, true) {
            return Err(fail("session already used"));
        }
        let cut = plan(request, &span, &self.policy)?;
        match recv(&mut self.party).await? {
            Control::Plan {
                hash,
                start,
                end,
                len,
            } if hash == wire::hash(request)
                && start == span.start
                && end == span.end
                && len == request.len() => {}
            _ => return Err(fail("canonical request plan mismatch")),
        }
        self.old
            .encrypt(&mut self.party, &request[..cut], Some(credential), span)
            .await?;
        if !matches!(recv(&mut self.party).await?, Control::Switched) {
            return Err(fail("KeyUpdate not delivered"));
        }
        self.party.reveal(self.next).await?;
        if !matches!(recv(&mut self.party).await?, Control::Delivered) {
            return Err(fail("request delivery incomplete"));
        }
        send(&mut self.party, Control::Delivered).await?;
        Ok(())
    }
}
