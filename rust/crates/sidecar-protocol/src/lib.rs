//! Versioned capability negotiation between TokenHive Go services and Rust
//! MPC-TLS sidecars.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

mod delivery;
mod rpc;
mod wire;
pub use delivery::{DELIVERY_ACK_PAYLOAD_SIZE, DeliveryAck, DeliveryAckError};
pub use rpc::{
    MAX_CANCEL_REASON_SIZE, MAX_COMMAND_SIZE, MAX_HELLO_SIZE, MAX_STREAM_SIZE, Operation,
    RpcCommand, RpcError, RpcHello, RpcHelloAck, RpcResult, RpcStatus, StreamInput, accept_hello,
    read_command, read_stream, write_result, write_stream,
};
pub use wire::{
    Frame, FrameReader, FrameType, FrameWriter, MAX_DATA_FRAME_SIZE, MAX_PAYLOAD_SIZE, WireError,
};

/// Current local sidecar protocol version.
pub const PROTOCOL_VERSION: u16 = 1;
/// The only TLS version accepted by the first implementation.
pub const TLS_1_2: &str = "1.2";
/// Explicit TLS 1.3 engine version.
pub const TLS_1_3: &str = "1.3";
/// Credential epoch separated from the public body using KeyUpdate.
pub const FEATURE_TLS13_KEY_UPDATE: &str = "tls13-keyupdate";
/// Hub garbling with masked and MAC-authenticated outputs.
pub const FEATURE_AUTHENTICATED_MPC_OUTPUT: &str = "authenticated-mpc-output";
/// Shared keyed HMAC prefix states and MPC schedule revision 2.
pub const FEATURE_TLS13_KEYED_HMAC_STATE: &str = "tls13-keyed-hmac-state";
/// Required feature for one-way server traffic key release.
pub const FEATURE_SERVER_KEY_RELEASE: &str = "server-key-release";
/// Required feature for request-direction selective encryption.
pub const FEATURE_SELECTIVE_REQUEST: &str = "selective-request-encryption";
/// Required feature for canonical public-body records encrypted with decoded keystream.
pub const FEATURE_PUBLIC_REQUEST_BODY: &str = "public-request-body-keystream";
/// Required feature for dedicated full-duplex MPC and upstream attachments.
pub const FEATURE_BIDIRECTIONAL_ATTACHMENTS: &str = "bidirectional-attachments";
/// Required feature for Hub-local authenticated response streaming.
pub const FEATURE_AUTHENTICATED_RESPONSE: &str = "authenticated-response-channel";
/// Required feature for Provider upstream write acknowledgements.
pub const FEATURE_PROVIDER_DELIVERY_ACK: &str = "provider-delivery-ack";
/// Nonce-bound client AES evaluated before the session becomes READY.
pub const FEATURE_PRECOMPUTED_CLIENT_AES: &str = "precomputed-client-aes";

/// Fixed baseline selective-MPC request capacity in plaintext bytes.
pub const BASELINE_MAX_REQUEST_BYTES: u32 = 4 << 10;
/// Fixed baseline number of client-direction records reserved per session.
pub const BASELINE_MAX_REQUEST_RECORDS: u16 = 4;
/// Large selective-MPC request capacity in plaintext bytes.
pub const LARGE_MAX_REQUEST_BYTES: u32 = 5 << 20;
/// Records reserved for a split header and a 5 MiB body, including handshake records.
pub const LARGE_MAX_REQUEST_RECORDS: u16 = 323;
/// Fixed baseline authenticated response capacity in ciphertext bytes.
pub const BASELINE_MAX_RESPONSE_BYTES: u32 = 16 << 20;
/// Fixed baseline online server-record capacity used during authentication.
pub const BASELINE_MAX_RESPONSE_RECORDS_ONLINE: u16 = 6;

const SUPPORTED_CIPHER_SUITES: [&str; 2] = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
];

/// Sidecar party role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Hub-side TLS verifier and response decryptor.
    Hub,
    /// Provider-side credential owner and network relay.
    Provider,
}

/// Engine security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineMode {
    /// TLS 1.2 selective MPC mode.
    Tls12SelectiveMpc,
    /// TLS 1.3 selective MPC with authenticated outputs and KeyUpdate.
    Tls13SelectiveMpc,
}

impl EngineMode {
    fn version(self) -> &'static str {
        match self {
            Self::Tls12SelectiveMpc => TLS_1_2,
            Self::Tls13SelectiveMpc => TLS_1_3,
        }
    }
    fn suites(self) -> &'static [&'static str] {
        match self {
            Self::Tls12SelectiveMpc => &SUPPORTED_CIPHER_SUITES,
            Self::Tls13SelectiveMpc => &["TLS_AES_128_GCM_SHA256"],
        }
    }
    fn features(self) -> Vec<&'static str> {
        let mut features = vec![
            FEATURE_SERVER_KEY_RELEASE,
            FEATURE_SELECTIVE_REQUEST,
            FEATURE_BIDIRECTIONAL_ATTACHMENTS,
            FEATURE_AUTHENTICATED_RESPONSE,
            FEATURE_PROVIDER_DELIVERY_ACK,
        ];
        match self {
            Self::Tls12SelectiveMpc => {
                features.extend([FEATURE_PUBLIC_REQUEST_BODY, FEATURE_PRECOMPUTED_CLIENT_AES])
            }
            Self::Tls13SelectiveMpc => features.extend([
                FEATURE_TLS13_KEY_UPDATE,
                FEATURE_AUTHENTICATED_MPC_OUTPUT,
                FEATURE_TLS13_KEYED_HMAC_STATE,
            ]),
        }
        features
    }
}

/// Resource bounds committed by both MPC parties before a session starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MpcCapacity {
    /// Maximum total client application plaintext committed by MPC.
    pub max_request_bytes: u32,
    /// Maximum number of client-direction records committed by MPC.
    pub max_request_records: u16,
    /// Maximum total authenticated server ciphertext retained per session.
    pub max_response_bytes: u32,
    /// Maximum server records processed in the online handshake phase.
    pub max_response_records_online: u16,
}

impl MpcCapacity {
    /// Returns the small capacity profile supported by protocol v1.
    pub const fn baseline() -> Self {
        Self {
            max_request_bytes: BASELINE_MAX_REQUEST_BYTES,
            max_request_records: BASELINE_MAX_REQUEST_RECORDS,
            max_response_bytes: BASELINE_MAX_RESPONSE_BYTES,
            max_response_records_online: BASELINE_MAX_RESPONSE_RECORDS_ONLINE,
        }
    }

    /// Returns the 5 MiB public-body capacity profile supported by protocol v1.
    pub const fn large() -> Self {
        Self {
            max_request_bytes: LARGE_MAX_REQUEST_BYTES,
            max_request_records: LARGE_MAX_REQUEST_RECORDS,
            max_response_bytes: BASELINE_MAX_RESPONSE_BYTES,
            max_response_records_online: BASELINE_MAX_RESPONSE_RECORDS_ONLINE,
        }
    }

    /// Returns an exact profile for a supported request-byte budget.
    pub const fn for_request_bytes(bytes: u32) -> Option<Self> {
        if !matches!(bytes, 4096 | 16384 | 65536 | 262144 | 1048576 | 5242880) {
            return None;
        }
        Some(Self {
            max_request_bytes: bytes,
            max_request_records: (bytes.div_ceil(16384) + 3) as u16,
            max_response_bytes: BASELINE_MAX_RESPONSE_BYTES,
            max_response_records_online: BASELINE_MAX_RESPONSE_RECORDS_ONLINE,
        })
    }

    /// Resolves the named process capacity profile.
    pub fn from_profile(name: &str) -> Option<Self> {
        let bytes = match name {
            "baseline" => 4096,
            "16k" => 16384,
            "64k" => 65536,
            "256k" => 262144,
            "1m" => 1048576,
            "5m" => 5242880,
            _ => return None,
        };
        Self::for_request_bytes(bytes)
    }

    /// Returns whether this is an exact locally supported capacity profile.
    pub const fn is_supported(self) -> bool {
        let Some(profile) = Self::for_request_bytes(self.max_request_bytes) else {
            return false;
        };
        self.max_request_records == profile.max_request_records
            && self.max_response_bytes == profile.max_response_bytes
            && self.max_response_records_online == profile.max_response_records_online
    }
}

/// Capabilities announced by one sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Local RPC protocol version.
    pub protocol_version: u16,
    /// Sidecar role.
    pub role: Role,
    /// Security mode implemented by the sidecar.
    pub engine_mode: EngineMode,
    /// Supported TLS protocol versions.
    pub tls_versions: Vec<String>,
    /// Supported TLS cipher suite names.
    pub cipher_suites: Vec<String>,
    /// Supported TokenHive protocol features.
    pub features: Vec<String>,
    /// Exact MPC preprocessing and authenticated response bounds.
    pub mpc_capacity: MpcCapacity,
}

impl Capabilities {
    /// Creates the capabilities required for M1 through M3.
    pub fn selective_mpc(role: Role) -> Self {
        Self::selective_mpc_with_capacity(role, MpcCapacity::baseline())
    }

    /// Creates TLS 1.3 capabilities only for an explicitly selected engine.
    pub fn tls13_with_capacity(role: Role, mpc_capacity: MpcCapacity) -> Self {
        assert!(mpc_capacity.is_supported(), "unsupported MPC capacity");
        let mode = EngineMode::Tls13SelectiveMpc;
        Self {
            protocol_version: PROTOCOL_VERSION,
            role,
            engine_mode: mode,
            tls_versions: vec![mode.version().into()],
            cipher_suites: mode.suites().iter().map(|s| (*s).into()).collect(),
            features: mode.features().iter().map(|s| (*s).into()).collect(),
            mpc_capacity,
        }
    }

    /// Creates selective-MPC capabilities for an exact supported capacity profile.
    pub fn selective_mpc_with_capacity(role: Role, mpc_capacity: MpcCapacity) -> Self {
        assert!(mpc_capacity.is_supported(), "unsupported MPC capacity");
        Self {
            protocol_version: PROTOCOL_VERSION,
            role,
            engine_mode: EngineMode::Tls12SelectiveMpc,
            tls_versions: vec![TLS_1_2.to_owned()],
            cipher_suites: SUPPORTED_CIPHER_SUITES
                .iter()
                .map(|suite| (*suite).to_owned())
                .collect(),
            features: vec![
                FEATURE_SERVER_KEY_RELEASE.to_owned(),
                FEATURE_SELECTIVE_REQUEST.to_owned(),
                FEATURE_PUBLIC_REQUEST_BODY.to_owned(),
                FEATURE_BIDIRECTIONAL_ATTACHMENTS.to_owned(),
                FEATURE_AUTHENTICATED_RESPONSE.to_owned(),
                FEATURE_PROVIDER_DELIVERY_ACK.to_owned(),
                FEATURE_PRECOMPUTED_CLIENT_AES.to_owned(),
            ],
            mpc_capacity,
        }
    }
}

/// Result of successful capability negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    /// Selected local RPC protocol version.
    pub protocol_version: u16,
    /// Selected TLS version.
    pub tls_version: String,
    /// Mutually supported cipher suites, preserving Hub preference order.
    pub cipher_suites: Vec<String>,
    /// Capacity profile committed by both parties.
    pub mpc_capacity: MpcCapacity,
}

/// Validates Hub and Provider capabilities without allowing downgrade.
pub fn negotiate(
    hub: &Capabilities,
    provider: &Capabilities,
) -> Result<NegotiatedCapabilities, NegotiationError> {
    if hub.role != Role::Hub || provider.role != Role::Provider {
        return Err(NegotiationError::Role);
    }
    if hub.mpc_capacity != provider.mpc_capacity {
        return Err(NegotiationError::CapacityMismatch);
    }
    validate_capabilities(hub, Role::Hub)?;
    validate_capabilities(provider, Role::Provider)?;
    if hub.engine_mode != provider.engine_mode {
        return Err(NegotiationError::EngineMode);
    }

    let provider_suites: BTreeSet<_> = provider.cipher_suites.iter().map(String::as_str).collect();
    let cipher_suites: Vec<_> = hub
        .cipher_suites
        .iter()
        .filter(|suite| {
            hub.engine_mode.suites().contains(&suite.as_str())
                && provider_suites.contains(suite.as_str())
        })
        .cloned()
        .collect();
    if cipher_suites.is_empty() {
        return Err(NegotiationError::CipherSuite);
    }

    Ok(NegotiatedCapabilities {
        protocol_version: PROTOCOL_VERSION,
        tls_version: hub.engine_mode.version().to_owned(),
        cipher_suites,
        mpc_capacity: hub.mpc_capacity,
    })
}

/// Validates one sidecar's role and required selective-MPC capabilities.
pub fn validate_capabilities(
    capabilities: &Capabilities,
    expected_role: Role,
) -> Result<(), NegotiationError> {
    if capabilities.role != expected_role {
        return Err(NegotiationError::Role);
    }
    if capabilities.protocol_version != PROTOCOL_VERSION {
        return Err(NegotiationError::ProtocolVersion);
    }
    if capabilities.tls_versions != [capabilities.engine_mode.version()] {
        return Err(NegotiationError::TlsVersion);
    }
    if !capabilities.mpc_capacity.is_supported() {
        return Err(NegotiationError::Capacity);
    }
    for feature in capabilities.engine_mode.features() {
        if !capabilities.features.iter().any(|item| item == feature) {
            return Err(NegotiationError::MissingFeature(feature));
        }
    }
    if !capabilities
        .cipher_suites
        .iter()
        .any(|suite| capabilities.engine_mode.suites().contains(&suite.as_str()))
    {
        return Err(NegotiationError::CipherSuite);
    }
    Ok(())
}

/// Capability negotiation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NegotiationError {
    /// Hub and Provider roles were not presented in the expected order.
    #[error("invalid Hub/Provider sidecar roles")]
    Role,
    /// The local sidecar RPC versions do not match the required version.
    #[error("unsupported sidecar protocol version")]
    ProtocolVersion,
    /// A sidecar is not running the selective MPC engine.
    #[error("unsupported sidecar engine mode")]
    EngineMode,
    /// A sidecar advertised versions inconsistent with its selected engine.
    #[error("each sidecar must exclusively advertise its selected engine TLS version")]
    TlsVersion,
    /// A required protocol feature is absent.
    #[error("missing required feature {0}")]
    MissingFeature(&'static str),
    /// No supported AES-128-GCM cipher suite is shared.
    #[error("no mutually supported cipher suite")]
    CipherSuite,
    /// A sidecar advertised a capacity profile unsupported by protocol v1.
    #[error("unsupported MPC capacity profile")]
    Capacity,
    /// Hub and Provider advertised different resource commitments.
    #[error("Hub and Provider MPC capacity profiles do not match")]
    CapacityMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_v1_releases_allow_optional_features_without_accepting_unknown_protocols() {
        for tls13 in [false, true] {
            for upgraded in [Role::Hub, Role::Provider] {
                let (mut hub, mut provider) = if tls13 {
                    (
                        Capabilities::tls13_with_capacity(Role::Hub, MpcCapacity::large()),
                        Capabilities::tls13_with_capacity(Role::Provider, MpcCapacity::large()),
                    )
                } else {
                    (
                        Capabilities::selective_mpc(Role::Hub),
                        Capabilities::selective_mpc(Role::Provider),
                    )
                };
                match upgraded {
                    Role::Hub => hub.features.push("optional-warm-stage-metrics".into()),
                    Role::Provider => provider.features.push("optional-warm-stage-metrics".into()),
                }
                assert!(negotiate(&hub, &provider).is_ok());
                provider.protocol_version += 1;
                assert_eq!(
                    negotiate(&hub, &provider),
                    Err(NegotiationError::ProtocolVersion)
                );
            }
        }
    }

    #[test]
    fn fixture_matches_wire_contract() {
        let fixture = include_str!("../../../../testdata/sidecar-capabilities.json");
        let parsed: Capabilities = serde_json::from_str(fixture).unwrap();
        assert_eq!(parsed, Capabilities::selective_mpc(Role::Hub));
    }

    #[test]
    fn negotiates_without_downgrade() {
        let hub = Capabilities::selective_mpc(Role::Hub);
        let provider = Capabilities::selective_mpc(Role::Provider);
        let negotiated = negotiate(&hub, &provider).unwrap();
        assert_eq!(negotiated.tls_version, TLS_1_2);
        assert_eq!(negotiated.cipher_suites, hub.cipher_suites);
        assert_eq!(negotiated.mpc_capacity, MpcCapacity::baseline());
    }

    #[test]
    fn negotiates_large_public_body_capacity() {
        let hub = Capabilities::selective_mpc_with_capacity(Role::Hub, MpcCapacity::large());
        let provider =
            Capabilities::selective_mpc_with_capacity(Role::Provider, MpcCapacity::large());
        let negotiated = negotiate(&hub, &provider).unwrap();
        assert_eq!(negotiated.mpc_capacity, MpcCapacity::large());
        assert_eq!(negotiated.mpc_capacity.max_request_bytes, 5 << 20);
    }

    #[test]
    fn rejects_tls_1_3_advertisement() {
        let hub = Capabilities::selective_mpc(Role::Hub);
        let mut provider = Capabilities::selective_mpc(Role::Provider);
        provider.tls_versions.push("1.3".to_owned());
        assert_eq!(
            negotiate(&hub, &provider),
            Err(NegotiationError::TlsVersion)
        );
    }

    #[test]
    fn rejects_capacity_mismatch_and_unsupported_profile() {
        let hub = Capabilities::selective_mpc(Role::Hub);
        let mut provider = Capabilities::selective_mpc(Role::Provider);
        provider.mpc_capacity.max_request_bytes *= 2;
        assert_eq!(
            negotiate(&hub, &provider),
            Err(NegotiationError::CapacityMismatch)
        );

        let mut unsupported_hub = hub;
        unsupported_hub.mpc_capacity.max_response_bytes /= 2;
        assert_eq!(
            validate_capabilities(&unsupported_hub, Role::Hub),
            Err(NegotiationError::Capacity)
        );
    }
}

#[cfg(test)]
mod capacity_fixture_tests {
    use super::*;

    #[test]
    fn online_aes_peer_is_rejected_before_mpc_setup() {
        let hub = Capabilities::selective_mpc(Role::Hub);
        let mut provider = Capabilities::selective_mpc(Role::Provider);
        provider
            .features
            .retain(|feature| feature != FEATURE_PRECOMPUTED_CLIENT_AES);
        assert!(negotiate(&hub, &provider).is_err());
        assert!(validate_capabilities(&provider, Role::Provider).is_err());
    }

    #[test]
    fn intermediate_profiles_match_go_fixture() {
        #[derive(Deserialize)]
        struct Fixture {
            name: String,
            capacity: MpcCapacity,
        }
        let fixtures: Vec<Fixture> =
            serde_json::from_str(include_str!("../../../../testdata/mpc-capacities.json")).unwrap();
        assert_eq!(fixtures.len(), 6);
        for fixture in fixtures {
            let capacity = MpcCapacity::from_profile(&fixture.name).unwrap();
            assert_eq!(capacity, fixture.capacity);
            assert!(capacity.is_supported());
            let mut invalid = capacity;
            invalid.max_request_records += 1;
            assert!(!invalid.is_supported());
        }
    }
}

#[cfg(test)]
mod tls13_tests {
    use super::*;
    #[test]
    fn tls13_matches_go_fixture_and_negotiates() {
        let fixture: Capabilities = serde_json::from_str(include_str!(
            "../../../../testdata/sidecar-capabilities-tls13.json"
        ))
        .unwrap();
        let hub = Capabilities::tls13_with_capacity(Role::Hub, MpcCapacity::baseline());
        assert_eq!(fixture, hub);
        for profile in ["baseline", "16k", "64k", "256k", "1m", "5m"] {
            let capacity = MpcCapacity::from_profile(profile).unwrap();
            let hub = Capabilities::tls13_with_capacity(Role::Hub, capacity);
            let provider = Capabilities::tls13_with_capacity(Role::Provider, capacity);
            let selected = negotiate(&hub, &provider).unwrap();
            assert_eq!(selected.tls_version, TLS_1_3);
            assert_eq!(selected.mpc_capacity, capacity);
        }
    }
    #[test]
    fn tls13_rejects_incompatible_peers() {
        let hub = Capabilities::tls13_with_capacity(Role::Hub, MpcCapacity::baseline());
        let provider = Capabilities::tls13_with_capacity(Role::Provider, MpcCapacity::baseline());
        assert!(negotiate(&hub, &Capabilities::selective_mpc(Role::Provider)).is_err());
        for feature in [
            FEATURE_TLS13_KEY_UPDATE,
            FEATURE_AUTHENTICATED_MPC_OUTPUT,
            FEATURE_TLS13_KEYED_HMAC_STATE,
            FEATURE_PROVIDER_DELIVERY_ACK,
        ] {
            let mut peer = provider.clone();
            peer.features.retain(|f| f != feature);
            assert!(negotiate(&hub, &peer).is_err());
        }
        let mut peer = provider.clone();
        peer.tls_versions.push(TLS_1_2.into());
        assert!(negotiate(&hub, &peer).is_err());
        let mut peer = provider.clone();
        peer.cipher_suites = vec!["TLS_AES_256_GCM_SHA384".into()];
        assert!(negotiate(&hub, &peer).is_err());
        let mut peer = provider;
        peer.mpc_capacity = MpcCapacity::large();
        assert!(negotiate(&hub, &peer).is_err());
    }
}
