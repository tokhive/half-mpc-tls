//! Directional TLS 1.2 key release for TokenHive.
//!
//! The Hub is allowed to decode only server-to-client traffic material. The
//! client write key remains an MPC value and is intentionally absent from this
//! crate's public output types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

use mpc_tls::{SessionKeys, VerifiedHandshake};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFutureTyped, binary::Binary};
use mpz_vm_core::{Vm, prelude::*};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Plaintext server-to-client traffic material released only to Hub.
///
/// This type is deliberately not serializable. The sidecar must pass it to
/// the local record decryptor without crossing the Hub/Provider control link.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ServerTrafficKeys {
    write_key: [u8; 16],
    fixed_iv: [u8; 4],
}

impl ServerTrafficKeys {
    /// Borrows the TLS 1.2 AES-128-GCM server write key.
    pub fn write_key(&self) -> &[u8; 16] {
        &self.write_key
    }

    /// Borrows the four-byte TLS 1.2 GCM fixed IV (salt).
    pub fn fixed_iv(&self) -> &[u8; 4] {
        &self.fixed_iv
    }
}

impl fmt::Debug for ServerTrafficKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTrafficKeys")
            .field("write_key", &"[REDACTED]")
            .field("fixed_iv", &"[REDACTED]")
            .finish()
    }
}

/// A scheduled one-way decode of server traffic material.
///
/// Calling [`HubServerKeyRelease::schedule`] registers output decoding only in
/// the Hub VM. The Provider side must execute/flush its matching VM but must
/// not schedule a decode for these references.
pub struct HubServerKeyRelease {
    write_key: DecodeFutureTyped<BitVec, [u8; 16]>,
    fixed_iv: DecodeFutureTyped<BitVec, [u8; 4]>,
    decoded_write_key: Option<[u8; 16]>,
    decoded_fixed_iv: Option<[u8; 4]>,
}

impl HubServerKeyRelease {
    /// Builds a release gate from one-way MPC decode futures.
    ///
    /// The caller must ensure the matching Provider operations only send
    /// decoding information and cannot receive the clear values.
    pub fn from_decode_futures(
        write_key: DecodeFutureTyped<BitVec, [u8; 16]>,
        fixed_iv: DecodeFutureTyped<BitVec, [u8; 4]>,
    ) -> Self {
        Self {
            write_key,
            fixed_iv,
            decoded_write_key: None,
            decoded_fixed_iv: None,
        }
    }

    /// Schedules server key and fixed-IV decoding in the Hub VM.
    ///
    /// There is intentionally no equivalent client-key method.
    pub fn schedule(vm: &mut dyn Vm<Binary>, keys: &SessionKeys) -> Result<Self, KeyReleaseError> {
        let write_key = vm
            .decode(keys.server_write_key)
            .map_err(|error| KeyReleaseError::Schedule(error.to_string()))?;
        let fixed_iv = vm
            .decode(keys.server_write_iv)
            .map_err(|error| KeyReleaseError::Schedule(error.to_string()))?;

        Ok(Self::from_decode_futures(write_key, fixed_iv))
    }

    /// Authorizes release after consuming a Hub-authenticated handshake proof.
    pub fn authorize(self, proof: VerifiedHandshake) -> AuthorizedServerKeyRelease {
        AuthorizedServerKeyRelease {
            release: Some(self),
            server_name: proof.server_name().clone(),
        }
    }

    #[cfg(test)]
    fn authorize_for_test(
        self,
        server_name: tlsn_core::connection::ServerName,
    ) -> AuthorizedServerKeyRelease {
        AuthorizedServerKeyRelease {
            release: Some(self),
            server_name,
        }
    }

    fn try_take_decoded(&mut self) -> Result<Option<ServerTrafficKeys>, KeyReleaseError> {
        if self.decoded_write_key.is_none() {
            self.decoded_write_key = self
                .write_key
                .try_recv()
                .map_err(|error| KeyReleaseError::Decode(error.to_string()))?;
        }
        if self.decoded_fixed_iv.is_none() {
            self.decoded_fixed_iv = self
                .fixed_iv
                .try_recv()
                .map_err(|error| KeyReleaseError::Decode(error.to_string()))?;
        }

        match (self.decoded_write_key.take(), self.decoded_fixed_iv.take()) {
            (Some(write_key), Some(fixed_iv)) => Ok(Some(ServerTrafficKeys {
                write_key,
                fixed_iv,
            })),
            (write_key, fixed_iv) => {
                self.decoded_write_key = write_key;
                self.decoded_fixed_iv = fixed_iv;
                Ok(None)
            }
        }
    }
}

/// A server-key release authorized by a Hub-verified TLS handshake.
pub struct AuthorizedServerKeyRelease {
    release: Option<HubServerKeyRelease>,
    server_name: tlsn_core::connection::ServerName,
}

impl AuthorizedServerKeyRelease {
    /// Returns the authenticated upstream DNS name.
    pub fn server_name(&self) -> &tlsn_core::connection::ServerName {
        &self.server_name
    }

    /// Returns decoded keys once both outputs are available.
    ///
    /// `Ok(None)` means more VM progress is required. Once this method returns
    /// key material, all later calls fail so the release cannot be replayed.
    pub fn try_take(&mut self) -> Result<Option<ServerTrafficKeys>, KeyReleaseError> {
        let release = self
            .release
            .as_mut()
            .ok_or(KeyReleaseError::AlreadyReleased)?;
        let material = release.try_take_decoded()?;
        if material.is_some() {
            self.release = None;
        }
        Ok(material)
    }
}

/// Failure while scheduling or receiving directional key material.
#[derive(Debug, thiserror::Error)]
pub enum KeyReleaseError {
    /// The VM rejected output scheduling.
    #[error("failed to schedule Hub server-key release: {0}")]
    Schedule(String),
    /// The scheduled VM output failed.
    #[error("failed to decode Hub server-key release: {0}")]
    Decode(String),
    /// The one-shot release was already consumed.
    #[error("Hub server-key release was already consumed")]
    AlreadyReleased,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_memory_core::{Array, MemoryExt, ViewExt, binary::U8};
    use tlsn_core::connection::{DnsName, ServerName};

    const SERVER_KEY: [u8; 16] = [0x42; 16];
    const SERVER_IV: [u8; 4] = [0x24; 4];

    #[tokio::test]
    async fn releases_only_server_material_to_hub_api() {
        let (mut hub_context, mut provider_context) = test_st_context(8);
        let mut hub_vm = IdealVm::new();
        let mut provider_vm = IdealVm::new();

        let hub_keys = allocate_session_keys(&mut hub_vm);
        let provider_keys = allocate_session_keys(&mut provider_vm);
        mark_hub_blind(&mut hub_vm, &hub_keys);
        assign_provider_inputs(&mut provider_vm, &provider_keys);

        let release = HubServerKeyRelease::schedule(&mut hub_vm, &hub_keys).unwrap();
        let server_name = ServerName::Dns(DnsName::try_from("api.example.com").unwrap());
        let mut release = release.authorize_for_test(server_name);
        assert_eq!(release.server_name().to_string(), "api.example.com");
        assert!(release.try_take().unwrap().is_none());

        tokio::try_join!(
            hub_vm.flush(&mut hub_context),
            provider_vm.flush(&mut provider_context)
        )
        .unwrap();

        let material = release.try_take().unwrap().unwrap();
        assert_eq!(material.write_key(), &SERVER_KEY);
        assert_eq!(material.fixed_iv(), &SERVER_IV);
        assert!(!format!("{material:?}").contains("42424242"));
        assert!(matches!(
            release.try_take(),
            Err(KeyReleaseError::AlreadyReleased)
        ));
    }

    #[test]
    fn zeroize_clears_material() {
        let mut material = ServerTrafficKeys {
            write_key: SERVER_KEY,
            fixed_iv: SERVER_IV,
        };
        material.zeroize();
        assert_eq!(material.write_key(), &[0; 16]);
        assert_eq!(material.fixed_iv(), &[0; 4]);
    }

    fn allocate_session_keys(vm: &mut IdealVm) -> SessionKeys {
        SessionKeys {
            client_write_key: vm.alloc().unwrap(),
            client_write_iv: vm.alloc().unwrap(),
            server_write_key: vm.alloc().unwrap(),
            server_write_iv: vm.alloc().unwrap(),
            server_write_mac_key: vm.alloc().unwrap(),
        }
    }

    fn mark_hub_blind(vm: &mut IdealVm, keys: &SessionKeys) {
        vm.mark_blind(keys.client_write_key).unwrap();
        vm.mark_blind(keys.client_write_iv).unwrap();
        vm.mark_blind(keys.server_write_key).unwrap();
        vm.mark_blind(keys.server_write_iv).unwrap();
        vm.mark_blind(keys.server_write_mac_key).unwrap();
        commit_all(vm, keys);
    }

    fn assign_provider_inputs(vm: &mut IdealVm, keys: &SessionKeys) {
        vm.mark_private(keys.client_write_key).unwrap();
        vm.mark_private(keys.client_write_iv).unwrap();
        vm.mark_private(keys.server_write_key).unwrap();
        vm.mark_private(keys.server_write_iv).unwrap();
        vm.mark_private(keys.server_write_mac_key).unwrap();
        vm.assign(keys.client_write_key, [0x11; 16]).unwrap();
        vm.assign(keys.client_write_iv, [0x12; 4]).unwrap();
        vm.assign(keys.server_write_key, SERVER_KEY).unwrap();
        vm.assign(keys.server_write_iv, SERVER_IV).unwrap();
        vm.assign(keys.server_write_mac_key, [0x13; 16]).unwrap();
        commit_all(vm, keys);
    }

    fn commit_all(vm: &mut IdealVm, keys: &SessionKeys) {
        vm.commit(keys.client_write_key).unwrap();
        vm.commit(keys.client_write_iv).unwrap();
        vm.commit(keys.server_write_key).unwrap();
        vm.commit(keys.server_write_iv).unwrap();
        vm.commit(keys.server_write_mac_key).unwrap();
    }

    #[allow(dead_code)]
    fn assert_key_widths(
        _client: Array<U8, 16>,
        _client_iv: Array<U8, 4>,
        _server: Array<U8, 16>,
        _server_iv: Array<U8, 4>,
    ) {
    }
}
