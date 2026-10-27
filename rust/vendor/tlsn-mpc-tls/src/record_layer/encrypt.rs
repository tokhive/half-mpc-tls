use futures::TryFutureExt as _;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::{Vm, prelude::*};
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::{ContentType, ProtocolVersion};

use crate::{
    BoxFut, MpcTlsError,
    record_layer::{
        TagData,
        aead::{AeadError, ComputeTags, MpcAesGcm},
    },
};

#[allow(clippy::type_complexity)]
fn private(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    op: &EncryptOp,
) -> Result<BoxFut<Result<Vec<u8>, AeadError>>, MpcTlsError> {
    let (plaintext, ciphertext) = encrypter
        .apply_keystream(vm, op.explicit_nonce.clone(), op.len)
        .map_err(MpcTlsError::record_layer)?;

    if let Some(data) = op.plaintext.clone() {
        vm.assign(plaintext, data)
            .map_err(MpcTlsError::record_layer)?;
    }
    vm.commit(plaintext).map_err(MpcTlsError::record_layer)?;

    let ciphertext_fut = Box::pin(
        vm.decode(ciphertext)
            .map_err(MpcTlsError::record_layer)?
            .map_err(AeadError::tag),
    );

    Ok(ciphertext_fut)
}

#[allow(clippy::type_complexity)]
fn public(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    op: &EncryptOp,
) -> Result<BoxFut<Result<Vec<u8>, AeadError>>, MpcTlsError> {
    // Instead of computing the ciphertext in MPC, we only compute the keystream and
    // decode it for both parties. Each party then locally computes the ciphertext.

    let Some(plaintext) = op.plaintext.clone() else {
        return Err(MpcTlsError::record_layer(
            "plaintext must be provided in public mode",
        ));
    };

    let keystream = encrypter
        .take_keystream(vm, op.explicit_nonce.clone(), op.len)
        .map_err(MpcTlsError::record_layer)?;

    let keystream_fut = vm.decode(keystream).map_err(MpcTlsError::record_layer)?;
    let ciphertext_fut = {
        let plaintext = plaintext.clone();
        Box::pin(async move {
            let mut ciphertext = keystream_fut.await.map_err(AeadError::tag)?;
            ciphertext
                .iter_mut()
                .zip(plaintext)
                .for_each(|(a, b)| *a ^= b);

            Ok(ciphertext)
        })
    };

    Ok(ciphertext_fut)
}

#[allow(clippy::type_complexity)]
fn selective(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    op: &EncryptOp,
    leader_ranges: &[std::ops::Range<usize>],
) -> Result<BoxFut<Result<Vec<u8>, AeadError>>, MpcTlsError> {
    let plaintext = op.plaintext.as_deref().ok_or_else(|| {
        MpcTlsError::record_layer("local plaintext is required in selective mode")
    })?;
    let ciphertext = encrypter
        .apply_selective_keystream(vm, op.explicit_nonce.clone(), plaintext, leader_ranges)
        .map_err(MpcTlsError::record_layer)?;
    let ciphertext_fut = Box::pin(
        vm.decode(ciphertext)
            .map_err(MpcTlsError::record_layer)?
            .map_err(AeadError::tag),
    );

    Ok(ciphertext_fut)
}

pub(crate) fn encrypt(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    ops: &[EncryptOp],
) -> Result<ComputeTags, MpcTlsError> {
    let mut ciphertext_futs = Vec::new();
    let mut tags_data = Vec::new();
    for op in ops {
        match &op.mode {
            EncryptMode::Private => {
                ciphertext_futs.push(private(vm, encrypter, op)?);
            }
            EncryptMode::Public => {
                ciphertext_futs.push(public(vm, encrypter, op)?);
            }
            EncryptMode::Selective { leader_ranges } => {
                ciphertext_futs.push(selective(vm, encrypter, op, leader_ranges)?);
            }
        }
        tags_data.push(TagData {
            explicit_nonce: op.explicit_nonce.clone(),
            aad: op.aad.clone(),
        });
    }

    encrypter
        .compute_tags(vm, ciphertext_futs, tags_data)
        .map_err(MpcTlsError::record_layer)
}

pub(crate) struct EncryptOp {
    pub(crate) seq: u64,
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) mode: EncryptMode,
}

impl EncryptOp {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        seq: u64,
        typ: ContentType,
        version: ProtocolVersion,
        len: usize,
        plaintext: Option<Vec<u8>>,
        explicit_nonce: Vec<u8>,
        aad: Vec<u8>,
        mode: EncryptMode,
    ) -> Result<Self, MpcTlsError> {
        if let Some(plaintext) = &plaintext
            && plaintext.len() != len
        {
            return Err(MpcTlsError::record_layer(format!(
                "inconsistent plaintext length: {} != {}",
                plaintext.len(),
                len
            )));
        }

        if matches!(&mode, EncryptMode::Public | EncryptMode::Selective { .. })
            && plaintext.is_none()
        {
            return Err(MpcTlsError::record_layer(
                "plaintext must be provided in public or selective mode",
            ));
        }

        Ok(Self {
            seq,
            typ,
            version,
            len,
            plaintext,
            explicit_nonce,
            aad,
            mode,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EncryptMode {
    /// The encrypted plaintext is private.
    Private,
    /// The encrypted plaintext is public.
    Public,
    /// Public bytes come from the follower while the selected ranges come from the leader.
    Selective {
        /// Sorted, non-overlapping byte ranges owned by the leader.
        leader_ranges: Vec<std::ops::Range<usize>>,
    },
}
