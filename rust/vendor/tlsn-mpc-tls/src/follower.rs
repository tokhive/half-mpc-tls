use crate::{
    Config, MpcTlsError, Role, SelectiveFollowerControl, ServerRecordReceiver, SessionKeys, Vm,
    msg::{Message, PeerIdentity, StartHandshake},
    record_layer::{EncryptMode, RecordLayer, aead::MpcAesGcm},
    server_record::{ServerRecord, ServerRecordSender, channel as server_record_channel},
    utils::check_close_notify,
};
use hmac_sha256::{MSMode, Prf, PrfConfig, PrfOutput};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
use mpz_memory_core::{DecodeFutureTyped, MemoryExt};
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use serio::stream::IoStreamExt;
use std::mem;
use tls_core::msgs::enums::{ContentType, NamedGroup};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, HandshakeData, ServerName, TlsVersion},
    transcript::TlsTranscript,
    webpki::{RootCertStore, ServerCertVerifier},
};
use tokio::sync::oneshot;

use tracing::{debug, instrument};

// Maximum handshake time difference in seconds.
const MAX_TIME_DIFF: u64 = 5;
const MAX_CERTIFICATES: usize = 16;
const MAX_CERTIFICATE_SIZE: usize = 1 << 20;
const MAX_CERT_CHAIN_SIZE: usize = 4 << 20;
const MAX_SIGNATURE_SIZE: usize = 16 << 10;

/// MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollower {
    config: Config,
    ctx: Context,
    state: State,
    handshake_verifier: Option<HandshakeVerifier>,
    selective: SelectiveFollowerControl,
    server_record_sender: ServerRecordSender,
    server_record_receiver: Option<ServerRecordReceiver>,
}

/// A pending Hub-side verification of the TLS 1.2 handshake.
///
/// This resolves only after the Hub has independently verified both Finished
/// messages, the certificate chain, the target DNS name, and the certificate
/// signature over the current ECDHE key exchange.
pub struct HandshakeVerification {
    receiver: oneshot::Receiver<Result<VerifiedHandshake, MpcTlsError>>,
}

impl HandshakeVerification {
    /// Waits for the authenticated handshake boundary.
    pub async fn wait(self) -> Result<VerifiedHandshake, MpcTlsError> {
        self.receiver
            .await
            .map_err(|_| MpcTlsError::hs("connection ended before handshake verification"))?
    }
}

/// Proof that the Hub-side follower authenticated the upstream TLS handshake.
///
/// Fields are private so only this crate can mint the proof. It is intended to
/// be consumed by the directional key-release gate.
#[derive(Debug)]
pub struct VerifiedHandshake {
    server_name: ServerName,
}

impl VerifiedHandshake {
    /// Returns the DNS identity authenticated by the Hub.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }
}

#[derive(Debug)]
struct HandshakeVerifier {
    server_name: ServerName,
    cert_verifier: ServerCertVerifier,
    sender: oneshot::Sender<Result<VerifiedHandshake, MpcTlsError>>,
}

impl MpcTlsFollower {
    /// Creates a new follower.
    pub fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: CS,
        cot_recv: (CR, CR, CR),
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Follower,
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.0),
            ))),
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send)),
            )),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = Prf::new(PrfConfig::new(config.prf, MSMode::Standard));

        let encrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.1),
            ))),
            Role::Follower,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.2),
            ))),
            Role::Follower,
        );

        let record_layer = RecordLayer::new(Role::Follower, encrypter, decrypter);

        let (server_record_sender, server_record_receiver) = server_record_channel();
        Self {
            config,
            ctx,
            state: State::Init {
                vm,
                ke,
                prf,
                record_layer,
            },
            handshake_verifier: None,
            selective: SelectiveFollowerControl::default(),
            server_record_sender,
            server_record_receiver: Some(server_record_receiver),
        }
    }

    /// Returns the control used to authorize one selective application request.
    pub fn selective_control(&self) -> SelectiveFollowerControl {
        self.selective.clone()
    }

    /// Takes the Hub-only stream of encrypted server records after the handshake.
    pub fn take_server_records(&mut self) -> Result<ServerRecordReceiver, MpcTlsError> {
        self.server_record_receiver
            .take()
            .ok_or_else(|| MpcTlsError::state("server record receiver was already taken"))
    }

    /// Configures Hub-side upstream authentication and returns its completion
    /// handle. This must be called before [`MpcTlsFollower::run`].
    pub fn verify_handshake(
        &mut self,
        server_name: ServerName,
        roots: &RootCertStore,
    ) -> Result<HandshakeVerification, MpcTlsError> {
        if self.handshake_verifier.is_some() {
            return Err(MpcTlsError::state(
                "handshake verification is already configured",
            ));
        }

        let cert_verifier =
            ServerCertVerifier::new(roots).map_err(|error| MpcTlsError::hs(error.to_string()))?;
        let (sender, receiver) = oneshot::channel();
        self.handshake_verifier = Some(HandshakeVerifier {
            server_name,
            cert_verifier,
            sender,
        });

        Ok(HandshakeVerification { receiver })
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Init {
            vm,
            mut ke,
            mut prf,
            mut record_layer,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in init state to allocate"));
        };

        let (keys, cf_vd, sf_vd, sw_mac_key) = {
            let vm = &mut (*vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?);

            let pms = ke.alloc(vm)?;
            let PrfOutput { keys, cf_vd, sf_vd } = prf.alloc_pms(vm, pms)?;
            record_layer.set_keys(
                keys.client_write_key,
                keys.client_iv,
                keys.server_write_key,
                keys.server_iv,
            )?;

            let cf_vd = vm.decode(cf_vd).map_err(MpcTlsError::alloc)?;
            let sf_vd = vm.decode(sf_vd).map_err(MpcTlsError::alloc)?;

            let server_write_mac_key = record_layer.alloc(
                vm,
                self.config.max_sent_records,
                self.config.max_recv_records_online,
                self.config.max_sent,
                self.config.max_recv_online,
                self.config.max_recv,
            )?;

            (keys, cf_vd, sf_vd, server_write_mac_key)
        };

        let keys: SessionKeys = SessionKeys {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_write_mac_key: sw_mac_key,
        };

        self.state = State::Setup {
            vm,
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
        };

        Ok(keys)
    }

    /// Preprocesses the connection.
    #[instrument(skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup {
            vm,
            mut ke,
            prf,
            mut record_layer,
            cf_vd,
            sf_vd,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in setup state to preprocess"));
        };

        let (ke, record_layer, _) = {
            let mut vm = vm
                .clone()
                .try_lock_owned()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;
            self.ctx
                .try_join3(
                    move |ctx| {
                        Box::pin(async move {
                            ke.setup(ctx)
                                .await
                                .map(|_| ke)
                                .map_err(MpcTlsError::preprocess)
                        })
                    },
                    move |ctx| {
                        Box::pin(async move {
                            record_layer
                                .preprocess(ctx)
                                .await
                                .map(|_| record_layer)
                                .map_err(MpcTlsError::preprocess)
                        })
                    },
                    move |ctx| {
                        Box::pin(async move {
                            vm.preprocess(ctx).await.map_err(MpcTlsError::preprocess)?;
                            vm.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                            Ok::<_, MpcTlsError>(())
                        })
                    },
                )
                .await
                .map_err(MpcTlsError::hs)??
        };

        self.state = State::Ready {
            vm,
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
        };

        Ok(())
    }

    /// Runs the follower.
    #[instrument(skip_all, err)]
    pub async fn run(mut self) -> Result<(Context, TlsTranscript), MpcTlsError> {
        let State::Ready {
            vm,
            mut ke,
            mut prf,
            mut record_layer,
            cf_vd: mut cf_vd_fut,
            sf_vd: mut sf_vd_fut,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in ready state to run"));
        };

        let mut time = None;
        let mut client_random = None;
        let mut server_random = None;
        let mut server_key = None;
        let mut expected_cf_vd = None;
        let mut expected_sf_vd = None;
        let mut peer_identity = None;
        let mut traffic_started = false;
        loop {
            let msg: Message = self.ctx.io_mut().expect_next().await?;
            match msg {
                Message::SetClientRandom(random) => {
                    if client_random.is_some() {
                        return Err(MpcTlsError::hs("client random already set"));
                    }

                    prf.set_client_random(random.random);
                    client_random = Some(random.random);
                }
                Message::StartHandshake(StartHandshake { time: prover_time }) => {
                    if time.is_some() {
                        return Err(MpcTlsError::hs("time already set"));
                    }

                    let this_time = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();

                    if prover_time.abs_diff(this_time) > MAX_TIME_DIFF {
                        return Err(MpcTlsError::hs("handshake time difference exceeds limit"));
                    }

                    time = Some(prover_time);
                }
                Message::SetServerRandom(random) => {
                    if server_random.is_some() {
                        return Err(MpcTlsError::hs("server random already set"));
                    }

                    prf.set_server_random(random.random)?;
                    server_random = Some(random.random);
                }
                Message::SetServerKey(key) => {
                    if server_key.is_some() {
                        return Err(MpcTlsError::hs("server key already set"));
                    }

                    let key = key.key;
                    let NamedGroup::secp256r1 = key.group else {
                        return Err(MpcTlsError::hs("unsupported server key group"));
                    };

                    ke.set_server_key(
                        p256::PublicKey::from_sec1_bytes(&key.key)
                            .map_err(|_| MpcTlsError::hs("failed to parse server key"))?,
                    )?;

                    server_key = Some(key);

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    ke.compute_shares(&mut self.ctx).await?;
                    ke.assign(&mut (*vm))?;
                    if self.selective.is_required() {
                        record_layer.precompute_client(&mut *vm)?;
                    }

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    ke.finalize().await?;
                    record_layer.setup(&mut self.ctx).await?;
                }
                Message::ClientFinishedVd(vd) => {
                    if expected_cf_vd.is_some() {
                        return Err(MpcTlsError::hs("client finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_cf_hash(vd.handshake_hash)?;

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    expected_cf_vd = Some(
                        cf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("client finished VD not computed"))?,
                    );
                }
                Message::ServerFinishedVd(vd) => {
                    if expected_sf_vd.is_some() {
                        return Err(MpcTlsError::hs("server finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_sf_hash(vd.handshake_hash)?;

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    expected_sf_vd = Some(
                        sf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("server finished VD not computed"))?,
                    );
                }
                Message::PeerIdentity(identity) => {
                    if peer_identity.is_some() {
                        return Err(MpcTlsError::hs("peer identity already set"));
                    }
                    if expected_sf_vd.is_none() {
                        return Err(MpcTlsError::hs(
                            "peer identity was provided before server Finished",
                        ));
                    }
                    validate_peer_identity(&identity)?;
                    peer_identity = Some(identity);
                }
                Message::Encrypt(encrypt) => {
                    let (plaintext, mode) = if encrypt.typ == ContentType::ApplicationData
                        && self.selective.is_required()
                    {
                        let Some((template, planned)) = self
                            .selective
                            .next_record(encrypt.len)
                            .map_err(|error| MpcTlsError::peer(error.to_string()))?
                        else {
                            return Err(MpcTlsError::peer(
                                "application data was not authorized by the follower",
                            ));
                        };
                        validate_request_encrypt(
                            encrypt.mode,
                            encrypt.plaintext,
                            template,
                            planned,
                        )?
                    } else {
                        (encrypt.plaintext, encrypt.mode)
                    };
                    record_layer
                        .push_encrypt(encrypt.typ, encrypt.version, encrypt.len, plaintext, mode)
                        .map_err(MpcTlsError::record_layer)?;
                }
                Message::Decrypt(decrypt) => {
                    if traffic_started
                        && decrypt.typ == ContentType::ApplicationData
                        && self.selective.is_required()
                        && decrypt.mode != crate::record_layer::DecryptMode::Blind
                    {
                        return Err(MpcTlsError::peer(
                            "server application plaintext must remain blind",
                        ));
                    }
                    let server_record = traffic_started.then(|| {
                        ServerRecord::new(
                            0,
                            decrypt.typ.get_u8(),
                            decrypt.version.get_u16(),
                            decrypt.explicit_nonce.clone(),
                            decrypt.ciphertext.clone(),
                            decrypt.tag.clone(),
                        )
                    });
                    let sequence = record_layer
                        .push_decrypt(
                            decrypt.typ,
                            decrypt.version,
                            decrypt.explicit_nonce,
                            decrypt.ciphertext,
                            decrypt.tag,
                            decrypt.mode,
                        )
                        .map_err(MpcTlsError::record_layer)?;
                    if let Some(mut server_record) = server_record {
                        server_record.sequence = sequence;
                        self.server_record_sender
                            .try_send(server_record)
                            .map_err(|_| MpcTlsError::state("server record buffer unavailable"))?;
                    }
                }
                Message::StartTraffic => {
                    if traffic_started {
                        return Err(MpcTlsError::hs("traffic was already started"));
                    }
                    let time = time.ok_or_else(|| MpcTlsError::hs("time was not set"))?;
                    let client_random = client_random
                        .ok_or_else(|| MpcTlsError::hs("client random was not set"))?;
                    let server_random = server_random
                        .ok_or_else(|| MpcTlsError::hs("server random was not set"))?;
                    let server_key = server_key
                        .clone()
                        .ok_or_else(|| MpcTlsError::hs("server key was not set"))?;
                    let expected_cf_vd = expected_cf_vd
                        .ok_or_else(|| MpcTlsError::hs("client Finished was not computed"))?;
                    let expected_sf_vd = expected_sf_vd
                        .ok_or_else(|| MpcTlsError::hs("server Finished was not computed"))?;
                    let (sent_records, recv_records) = record_layer.handshake_records()?;

                    let binding = CertBinding::V1_2(CertBindingV1_2 {
                        client_random,
                        server_random,
                        server_ephemeral_key: server_key.try_into().map_err(MpcTlsError::hs)?,
                    });
                    let transcript = TlsTranscript::builder()
                        .time(time)
                        .version(TlsVersion::V1_2)
                        .certificate_binding(binding.clone())
                        .records_sent(sent_records)
                        .records_recv(recv_records)
                        .build()
                        .map_err(MpcTlsError::hs)?;

                    if transcript.cf_vd() != Some(expected_cf_vd.as_slice()) {
                        return Err(MpcTlsError::peer("client Finished is incorrect"));
                    }
                    if transcript.sf_vd() != Some(expected_sf_vd.as_slice()) {
                        return Err(MpcTlsError::peer("server Finished is incorrect"));
                    }

                    if let Some(handshake_verifier) = self.handshake_verifier.take() {
                        let PeerIdentity { certs, signature } = peer_identity
                            .take()
                            .ok_or_else(|| MpcTlsError::hs("peer identity was not provided"))?;
                        let handshake = HandshakeData {
                            certs,
                            sig: signature,
                            binding,
                        };
                        #[allow(irrefutable_let_patterns)]
                        let CertBinding::V1_2(binding) = handshake.binding.clone() else {
                            unreachable!("only TLS 1.2 is supported")
                        };
                        if let Err(error) = handshake.verify(
                            &handshake_verifier.cert_verifier,
                            time,
                            &binding.server_ephemeral_key,
                            &handshake_verifier.server_name,
                        ) {
                            let message = error.to_string();
                            let _ = handshake_verifier
                                .sender
                                .send(Err(MpcTlsError::peer(message.clone())));
                            return Err(MpcTlsError::peer(message));
                        }

                        let _ = handshake_verifier.sender.send(Ok(VerifiedHandshake {
                            server_name: handshake_verifier.server_name,
                        }));
                    }
                    record_layer.start_traffic();
                    traffic_started = true;
                }
                Message::Flush { is_decrypting } => {
                    record_layer
                        .flush(&mut self.ctx, vm.clone(), is_decrypting)
                        .await?;
                    debug!("flushed record layer");
                }
                Message::CloseConnection => {
                    break;
                }
            }
        }

        debug!("committing");

        let (sent_records, recv_records) = record_layer.commit(&mut self.ctx, vm).await?;

        debug!("committed");

        let time = time.ok_or(MpcTlsError::hs("time was not set"))?;
        let server_key = server_key.ok_or(MpcTlsError::hs("server key not set"))?;
        let client_random = client_random.ok_or(MpcTlsError::hs("client random not set"))?;
        let server_random = server_random.ok_or(MpcTlsError::hs("client random not set"))?;
        let expected_cf_vd =
            expected_cf_vd.ok_or(MpcTlsError::hs("client finished VD not computed"))?;
        let expected_sf_vd =
            expected_sf_vd.ok_or(MpcTlsError::hs("server finished VD not computed"))?;

        let binding = CertBinding::V1_2(CertBindingV1_2 {
            client_random,
            server_random,
            server_ephemeral_key: server_key
                .try_into()
                .expect("only supported key scheme should have been accepted"),
        });

        let transcript = TlsTranscript::builder()
            .time(time)
            .version(TlsVersion::V1_2)
            .certificate_binding(binding)
            .records_sent(sent_records)
            .records_recv(recv_records)
            .build()
            .map_err(MpcTlsError::other)?;

        let cf_vd = transcript
            .cf_vd()
            .expect("client finished verify data should be available");

        if cf_vd != expected_cf_vd {
            return Err(MpcTlsError::peer("client verify data is incorrect"));
        }

        let sf_vd = transcript
            .sf_vd()
            .expect("server finished verify data should be available");
        if sf_vd != expected_sf_vd {
            return Err(MpcTlsError::peer("server verify data is incorrect"));
        }

        check_close_notify(transcript.sent())?;
        check_close_notify(transcript.recv())?;

        Ok((self.ctx, transcript))
    }
}

fn validate_peer_identity(identity: &PeerIdentity) -> Result<(), MpcTlsError> {
    if identity.certs.is_empty() || identity.certs.len() > MAX_CERTIFICATES {
        return Err(MpcTlsError::peer("invalid certificate chain length"));
    }

    let mut chain_size = 0usize;
    for cert in &identity.certs {
        if cert.0.is_empty() || cert.0.len() > MAX_CERTIFICATE_SIZE {
            return Err(MpcTlsError::peer("invalid certificate size"));
        }
        chain_size = chain_size
            .checked_add(cert.0.len())
            .ok_or_else(|| MpcTlsError::peer("certificate chain size overflow"))?;
    }
    if chain_size > MAX_CERT_CHAIN_SIZE {
        return Err(MpcTlsError::peer("certificate chain is too large"));
    }
    if identity.signature.sig.is_empty() || identity.signature.sig.len() > MAX_SIGNATURE_SIZE {
        return Err(MpcTlsError::peer("invalid server signature size"));
    }

    Ok(())
}

fn validate_request_encrypt(
    mode: EncryptMode,
    plaintext: Option<Vec<u8>>,
    template: Vec<u8>,
    planned: crate::selective::PlannedRecord,
) -> Result<(Option<Vec<u8>>, EncryptMode), MpcTlsError> {
    match (mode, planned) {
        (
            EncryptMode::Selective { leader_ranges },
            crate::selective::PlannedRecord::Selective(expected_ranges),
        ) if leader_ranges == expected_ranges => Ok((
            Some(template),
            EncryptMode::Selective {
                leader_ranges: expected_ranges,
            },
        )),
        (EncryptMode::Public, crate::selective::PlannedRecord::Public)
            if plaintext.as_deref() == Some(template.as_slice()) =>
        {
            Ok((Some(template), EncryptMode::Public))
        }
        (EncryptMode::Selective { .. }, crate::selective::PlannedRecord::Selective(_)) => Err(
            MpcTlsError::peer("selective encryption ranges do not match follower plan"),
        ),
        (EncryptMode::Public, crate::selective::PlannedRecord::Public) => Err(MpcTlsError::peer(
            "public application data does not match follower template",
        )),
        _ => Err(MpcTlsError::peer(
            "application data encryption mode does not match follower plan",
        )),
    }
}

enum State {
    Init {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
    },
    Setup {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Ready {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        mem::replace(self, State::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { .. } => f.debug_struct("Init").finish_non_exhaustive(),
            Self::Setup { .. } => f.debug_struct("Setup").finish_non_exhaustive(),
            Self::Ready { .. } => f.debug_struct("Ready").finish_non_exhaustive(),
            Self::Error => write!(f, "Error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn_core::connection::{ServerSignature, SignatureAlgorithm};
    use tlsn_core::webpki::CertificateDer;

    #[test]
    fn accepts_bounded_peer_identity() {
        assert!(validate_peer_identity(&identity(vec![vec![1; 512]])).is_ok());
    }

    #[test]
    fn rejects_empty_or_oversized_certificate_chain() {
        assert!(validate_peer_identity(&identity(Vec::new())).is_err());
        assert!(
            validate_peer_identity(&identity(vec![vec![1; MAX_CERTIFICATE_SIZE + 1]])).is_err()
        );
        assert!(validate_peer_identity(&identity(vec![vec![1]; MAX_CERTIFICATES + 1])).is_err());
    }

    #[test]
    fn rejects_oversized_signature() {
        let mut identity = identity(vec![vec![1; 512]]);
        identity.signature.sig = vec![1; MAX_SIGNATURE_SIZE + 1];
        assert!(validate_peer_identity(&identity).is_err());
    }

    #[test]
    fn public_request_record_must_match_hub_template() {
        let template = b"canonical public body".to_vec();
        assert!(
            validate_request_encrypt(
                EncryptMode::Public,
                Some(template.clone()),
                template.clone(),
                crate::selective::PlannedRecord::Public,
            )
            .is_ok()
        );

        assert!(
            validate_request_encrypt(
                EncryptMode::Public,
                Some(b"provider-modified body".to_vec()),
                template,
                crate::selective::PlannedRecord::Public,
            )
            .is_err()
        );
    }

    fn identity(certs: Vec<Vec<u8>>) -> PeerIdentity {
        PeerIdentity {
            certs: certs.into_iter().map(CertificateDer).collect(),
            signature: ServerSignature {
                alg: SignatureAlgorithm::ECDSA_NISTP256_SHA256,
                sig: vec![1; 64],
            },
        }
    }
}
