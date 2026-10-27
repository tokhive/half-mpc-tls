use std::{future::Future, ops::Range, sync::Arc};

use cipher::{Cipher, CtrBlock, Keystream, aes::Aes128};
use mpz_circuits::CircuitBuilder;
use mpz_common::{Context, Flush};
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    Vector,
    binary::{Binary, U8},
};
use mpz_share_conversion::ShareConvert;
use mpz_vm_core::{Call, Vm, prelude::*};
use tracing::instrument;

use crate::{
    Role,
    decode::OneTimePadShared,
    record_layer::{
        TagData,
        aead::{
            AeadError, Block, Ctr, Nonce,
            ghash::{ComputeTagData, ComputeTags, Ghash, MpcGhash, VerifyTagData, VerifyTags},
        },
    },
};

use super::warm::{WarmClient, take_stream};

#[allow(clippy::type_complexity)]
enum State {
    Init {
        ghash: Box<dyn Ghash + Send + Sync>,
    },
    Setup {
        leader_input: Vector<U8>,
        follower_input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash_key_share: OneTimePadShared<[u8; 16]>,
        ghash: Box<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
    },
    Ready {
        leader_input: Vector<U8>,
        follower_input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash: Arc<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

pub(crate) struct MpcAesGcm {
    role: Role,
    aes: Aes128,
    state: State,
    warm_client: Option<WarmClient>,
}

impl MpcAesGcm {
    /// Creates a new AES-GCM instance.
    pub(crate) fn new<C>(converter: C, role: Role) -> Self
    where
        C: ShareConvert<Gf2_128> + Flush + Send + Sync + 'static,
    {
        Self {
            role,
            aes: Aes128::default(),
            warm_client: None,
            state: State::Init {
                ghash: Box::new(MpcGhash::new(converter)),
            },
        }
    }

    /// Allocates resources.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine to allocate in.
    /// * `records` - Number of records to allocate.
    /// * `len` - Length of the input text in bytes.
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        records: usize,
        len: usize,
    ) -> Result<(), AeadError> {
        let State::Init { mut ghash } = self.state.take() else {
            return Err(AeadError::state("must be in init state to allocate"));
        };

        let zero_block: Array<U8, 16> = vm.alloc()?;
        vm.mark_public(zero_block)?;
        vm.assign(zero_block, [0u8; 16])?;
        vm.commit(zero_block)?;

        ghash.alloc()?;
        let ghash_key = self.aes.alloc_block(vm, zero_block)?;
        let ghash_key_share = OneTimePadShared::<[u8; 16]>::new(self.role, ghash_key, vm)?;

        // Allocate J0 secret sharing for GHASH.
        let mut j0s = Vec::with_capacity(records);
        for _ in 0..records {
            let j0 = self.aes.alloc_ctr_block(vm)?;
            let j0_shared = OneTimePadShared::<[u8; 16]>::new(self.role, j0.output, vm)?;

            j0s.push((j0, j0_shared));
        }

        // Allocate encryption/decryption.

        // Round up the length to the nearest multiple of the block size.
        let len = 16 * len.div_ceil(16);

        let leader_input = vm.alloc_vec::<U8>(len)?;
        let follower_input = vm.alloc_vec::<U8>(len)?;
        match self.role {
            Role::Leader => {
                vm.mark_private(leader_input)?;
                vm.mark_blind(follower_input)?;
            }
            Role::Follower => {
                vm.mark_blind(leader_input)?;
                vm.mark_private(follower_input)?;
            }
        }

        let keystream = self.aes.alloc_keystream(vm, len)?;

        self.state = State::Setup {
            leader_input,
            follower_input,
            keystream,
            j0s,
            ghash,
            ghash_key_share,
            ghash_key,
        };

        Ok(())
    }

    /// Assign public client nonces before the session key becomes available.
    /// AES outputs stay secret in the VM until the authorized record operation.
    pub(crate) fn precompute_client(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        capacity: usize,
    ) -> Result<(), AeadError> {
        let State::Setup {
            leader_input,
            follower_input,
            mut keystream,
            j0s,
            ghash_key_share,
            ghash,
            ghash_key,
        } = self.state.take()
        else {
            return Err(AeadError::state(
                "client precomputation requires setup state",
            ));
        };
        if self.warm_client.is_some() || j0s.len() < capacity.div_ceil(16384) + 2 {
            return Err(AeadError::state(
                "invalid or repeated client precomputation",
            ));
        }
        let warm = WarmClient::new(vm, &mut keystream, capacity)?;
        // Tags are popped in reverse allocation order. Each J0 is shared, not
        // decoded to either party, and bound to the same sequential nonce.
        for (sequence, (j0, _)) in j0s.iter().rev().enumerate() {
            assign_j0(vm, *j0, (sequence as u64).to_be_bytes())?;
        }
        self.warm_client = Some(warm);
        self.state = State::Setup {
            leader_input,
            follower_input,
            keystream,
            j0s,
            ghash_key_share,
            ghash,
            ghash_key,
        };
        Ok(())
    }

    pub(crate) async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        let State::Setup { ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in setup state to preprocess"));
        };

        ghash.preprocess(ctx).await?;

        Ok(())
    }

    pub(crate) fn set_key(&mut self, key: Array<U8, 16>) {
        self.aes.set_key(key);
    }

    pub(crate) fn set_iv(&mut self, iv: Array<U8, 4>) {
        self.aes.set_iv(iv);
    }

    pub(crate) async fn setup(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        let State::Setup {
            leader_input,
            follower_input,
            keystream,
            j0s,
            ghash_key_share,
            mut ghash,
            ghash_key,
        } = self.state.take()
        else {
            return Err(AeadError::state("must be in setup state to set up"));
        };

        let key = ghash_key_share.await.map_err(AeadError::tag)?;
        ghash.set_key(key.to_vec())?;
        ghash.setup(ctx).await?;

        self.state = State::Ready {
            leader_input,
            follower_input,
            keystream,
            j0s,
            ghash: Arc::from(ghash),
            ghash_key,
        };

        Ok(())
    }

    /// Returns `len` bytes of input and output text.
    ///
    /// The outer context is responsible for assigning to the input text.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn apply_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<(Vector<U8>, Vector<U8>), AeadError> {
        let State::Ready {
            leader_input,
            keystream,
            ..
        } = &mut self.state
        else {
            return Err(AeadError::state(
                "must be in ready state to apply keystream",
            ));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;
        let padding_len = padded_len - len;

        if padded_len > leader_input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                leader_input.len()
            )));
        }

        let mut input = leader_input.split_off(leader_input.len() - padded_len);
        let keystream = take_stream(
            vm,
            keystream,
            &mut self.warm_client,
            explicit_nonce,
            padded_len,
        )?;
        let mut output = keystream.apply(vm, input)?;

        // Assign zeroes to the padding.
        if padding_len > 0 {
            let padding = input.split_off(input.len() - padding_len);
            // To simplify the impl, we don't mark the padding as public, that's why only
            // the prover assigns it.
            if let Role::Leader = self.role {
                vm.assign(padding, vec![0; padding_len])?;
            }
            vm.commit(padding)?;
            output.truncate(len);
        }

        Ok((input, output))
    }

    /// Applies the keystream to a plaintext assembled from inputs owned by both parties.
    ///
    /// Bytes inside `leader_ranges` are supplied by the leader. Every other byte is
    /// supplied by the follower. The ranges are public circuit structure and must be
    /// sorted, non-overlapping, non-empty, and bounded by `len`.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn apply_selective_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        local_plaintext: &[u8],
        leader_ranges: &[Range<usize>],
    ) -> Result<Vector<U8>, AeadError> {
        let len = local_plaintext.len();
        validate_leader_ranges(len, leader_ranges)?;
        let State::Ready {
            leader_input,
            follower_input,
            keystream,
            ..
        } = &mut self.state
        else {
            return Err(AeadError::state(
                "must be in ready state to apply selective keystream",
            ));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;
        let padded_len = 16 * len.div_ceil(16);
        let padding_len = padded_len - len;
        if padded_len > leader_input.len() || padded_len > follower_input.len() {
            return Err(AeadError::cipher(format!(
                "selective input length exceeds allocated: {}",
                padded_len
            )));
        }

        let mut leader = leader_input.split_off(leader_input.len() - padded_len);
        let mut follower = follower_input.split_off(follower_input.len() - padded_len);
        let circuit = selective_plaintext_circuit(padded_len, leader_ranges);
        let plaintext: Vector<U8> = vm.call(
            Call::builder(Arc::new(circuit))
                .arg(leader)
                .arg(follower)
                .build()
                .expect("selective plaintext circuit input lengths are fixed"),
        )?;
        let keystream = take_stream(
            vm,
            keystream,
            &mut self.warm_client,
            explicit_nonce,
            padded_len,
        )?;
        let mut output = keystream.apply(vm, plaintext)?;

        if padding_len > 0 {
            let leader_padding = leader.split_off(leader.len() - padding_len);
            let follower_padding = follower.split_off(follower.len() - padding_len);
            match self.role {
                Role::Leader => vm.assign(leader_padding, vec![0; padding_len])?,
                Role::Follower => vm.assign(follower_padding, vec![0; padding_len])?,
            }
            vm.commit(leader_padding)?;
            vm.commit(follower_padding)?;
            output.truncate(len);
        }

        match self.role {
            Role::Leader => vm.assign(leader, local_plaintext.to_vec())?,
            Role::Follower => vm.assign(follower, local_plaintext.to_vec())?,
        }
        vm.commit(leader)?;
        vm.commit(follower)?;

        Ok(output)
    }

    /// Returns `len` bytes of keystream.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn take_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<Vector<U8>, AeadError> {
        let State::Ready {
            leader_input,
            keystream,
            ..
        } = &mut self.state
        else {
            return Err(AeadError::state("must be in ready state to take keystream"));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;

        if padded_len > leader_input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                leader_input.len()
            )));
        }

        let keystream = take_stream(vm, keystream, &mut self.warm_client, explicit_nonce, len)?;

        Ok(keystream.to_vector(vm, len)?)
    }

    /// Returns the VM reference to the GHASH key.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn ghash_key(&mut self) -> Result<Array<U8, 16>, AeadError> {
        let key = match self.state {
            State::Setup { ghash_key, .. } => ghash_key,
            State::Ready { ghash_key, .. } => ghash_key,
            _ => {
                return Err(AeadError::state(
                    "must be in setup or ready state to return ghash key",
                ));
            }
        };

        Ok(key)
    }

    /// Computes tags for the provided ciphertext. See
    /// [`verify_tags`](MpcAesGcm::verify_tags) for a method that verifies
    /// tags instead.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `ciphertext` - Ciphertext to compute the tag for.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn compute_tags<C>(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        ciphertexts: Vec<C>,
        data: Vec<TagData>,
    ) -> Result<ComputeTags, AeadError>
    where
        C: Future<Output = Result<Vec<u8>, AeadError>> + Send + Sync + 'static,
    {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to compute tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for (ciphertext, data) in ciphertexts.into_iter().zip(data) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            if let Some(warm) = &mut self.warm_client {
                warm.tag(explicit_nonce)?;
            } else {
                assign_j0(vm, j0, explicit_nonce)?;
            }

            tag_data.push(ComputeTagData {
                j0: j0_shared,
                ciphertext: Box::pin(ciphertext),
                aad: data.aad,
            });
        }

        let tags = ComputeTags::new(self.role, tag_data, ghash.clone());

        Ok(tags)
    }

    /// Verifies the tags for the provided ciphertexts.
    ///
    /// Ciphertexts are only authenticated from the leader's perspective.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `data` - Tag data associated with `tags`.
    /// * `ciphertexts` - Ciphertexts to verify the tags for.
    /// * `tags` - Tags to verify.
    pub(crate) fn verify_tags(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: Vec<TagData>,
        ciphertexts: Vec<Vec<u8>>,
        tags: Vec<Vec<u8>>,
    ) -> Result<VerifyTags, AeadError> {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to verify tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() != tags.len() {
            return Err(AeadError::tag("ciphertext and tag length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for ((ciphertext, data), tag) in ciphertexts.into_iter().zip(data).zip(tags) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            assign_j0(vm, j0, explicit_nonce)?;

            tag_data.push(VerifyTagData {
                j0: j0_shared,
                ciphertext,
                aad: data.aad,
                tag,
            });
        }

        let tags = VerifyTags::new(self.role, tag_data, ghash.clone());

        Ok(tags)
    }
}

fn validate_leader_ranges(len: usize, ranges: &[Range<usize>]) -> Result<(), AeadError> {
    if len == 0 || ranges.is_empty() {
        return Err(AeadError::cipher(
            "selective plaintext requires non-empty input and leader ranges",
        ));
    }
    let mut previous_end = 0;
    for range in ranges {
        if range.start < previous_end || range.start >= range.end || range.end > len {
            return Err(AeadError::cipher(
                "selective plaintext leader ranges are invalid",
            ));
        }
        previous_end = range.end;
    }
    Ok(())
}

fn selective_plaintext_circuit(
    padded_len: usize,
    leader_ranges: &[Range<usize>],
) -> mpz_circuits::Circuit {
    let mut builder = CircuitBuilder::new();
    let bit_len = padded_len * 8;
    let leader = (0..bit_len)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    let follower = (0..bit_len)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();

    let mut range_index = 0;
    for byte in 0..padded_len {
        while range_index < leader_ranges.len() && byte >= leader_ranges[range_index].end {
            range_index += 1;
        }
        let from_leader =
            range_index < leader_ranges.len() && leader_ranges[range_index].contains(&byte);
        for bit in byte * 8..(byte + 1) * 8 {
            let selected = if from_leader {
                leader[bit]
            } else {
                follower[bit]
            };
            let output = builder.add_id_gate(selected);
            builder.add_output(output);
        }
    }

    builder
        .build()
        .expect("fixed selective plaintext circuit is valid")
}

fn assign_j0(
    vm: &mut dyn Vm<Binary>,
    j0: CtrBlock<Nonce, Ctr, Block>,
    explicit_nonce: [u8; 8],
) -> Result<(), AeadError> {
    vm.assign(j0.explicit_nonce, explicit_nonce)?;
    vm.commit(j0.explicit_nonce)?;
    vm.assign(j0.counter, 1u32.to_be_bytes())?;
    vm.commit(j0.counter)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::single_range_in_vec_init)]

    use super::*;
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInPlace, NewAead},
    };
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_ideal_vm::IdealVm;
    use mpz_memory_core::binary::U8;
    use mpz_share_conversion::ideal::ideal_share_convert;
    use rand::{SeedableRng, rngs::StdRng};
    use rstest::*;

    static SHORT_MSG: &[u8] = b"hello world";
    static LONG_MSG: &[u8] = b"this message exceeds one block in length";

    #[derive(Clone, Copy)]
    struct Vars {
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_encrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (msg_0, ct_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), msg.len())
                .unwrap();
            let (msg_1, ct_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), msg.len())
                .unwrap();

            vm_0.assign(msg_0, msg.to_vec()).unwrap();
            vm_0.commit(msg_0).unwrap();

            vm_1.commit(msg_1).unwrap();

            let ct_0 = vm_0.decode(ct_0).unwrap();
            let ct_1 = vm_1.decode(ct_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let ct_0 = ct_0.await.unwrap();
            let ct_1 = ct_1.await.unwrap();

            let (expected, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);
            assert_eq!(ct_0, expected);
            assert_eq!(ct_1, expected);
        }
    }

    #[tokio::test]
    async fn test_selective_aes_gcm_uses_only_authorized_party_bytes() {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);
        let key = [42u8; 16];
        let iv = [0u8; 4];
        let template = b"public:[000000]:public-tail";
        let mut leader_plaintext = b"forged:[SECRET]:forged-tail".to_vec();
        let leader_ranges = [8..14];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);
        leader.alloc(&mut vm_0, 1, 256).unwrap();
        follower.alloc(&mut vm_1, 1, 256).unwrap();
        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;
        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        leader_plaintext.resize(template.len(), b'!');
        let explicit_nonce = 7u64.to_be_bytes().to_vec();
        let ciphertext_0 = leader
            .apply_selective_keystream(
                &mut vm_0,
                explicit_nonce.clone(),
                &leader_plaintext,
                &leader_ranges,
            )
            .unwrap();
        let ciphertext_1 = follower
            .apply_selective_keystream(&mut vm_1, explicit_nonce.clone(), template, &leader_ranges)
            .unwrap();

        let ciphertext_0 = vm_0.decode(ciphertext_0).unwrap();
        let ciphertext_1 = vm_1.decode(ciphertext_1).unwrap();
        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        let mut expected_plaintext = template.to_vec();
        expected_plaintext[leader_ranges[0].clone()]
            .copy_from_slice(&leader_plaintext[leader_ranges[0].clone()]);
        let (expected_ciphertext, _) =
            expected(&key, &iv, &explicit_nonce, &expected_plaintext, &[]);
        assert_eq!(ciphertext_0.await.unwrap(), expected_ciphertext);
        assert_eq!(ciphertext_1.await.unwrap(), expected_ciphertext);
    }

    #[rstest]
    #[case::one_block(64, 16)]
    #[case::partial_block(64, 17)]
    #[case::short_tail(64, 63)]
    #[case::full_capacity(64, 64)]
    #[case::full_fragment(16384, 16384)]
    #[case::multiple_fragments(16401, 16401)]
    #[case::early_close(16401, 17)]
    #[tokio::test]
    async fn warm_records_match_aes_gcm_and_keep_selective_ownership(
        #[case] capacity: usize,
        #[case] request_len: usize,
    ) {
        use mpz_common::Task;
        let (mut ctx_0, mut ctx_1) = test_st_context(8);
        let key = [42u8; 16];
        let iv = [9u8; 4];
        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);
        let records = capacity.div_ceil(16384) + 2;
        leader.alloc(&mut vm_0, records, capacity + 32).unwrap();
        follower.alloc(&mut vm_1, records, capacity + 32).unwrap();
        leader.precompute_client(&mut vm_0, capacity).unwrap();
        follower.precompute_client(&mut vm_1, capacity).unwrap();
        // No application input has been assigned, nor any data stream decoded.
        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;
        assert!(!vm_0.wants_execute() && !vm_1.wants_execute());
        assert!(!vm_0.wants_flush() && !vm_1.wants_flush());
        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        let template = vec![b'p'; request_len];
        let plaintexts = std::iter::once(vec![0x14; 16])
            .chain(template.chunks(16384).map(<[u8]>::to_vec))
            .chain(std::iter::once(vec![1, 0]))
            .collect::<Vec<_>>();
        for (sequence, mut plaintext) in plaintexts.into_iter().enumerate() {
            let nonce = (sequence as u64).to_be_bytes().to_vec();
            let (ct_0, ct_1) = if sequence == 1 {
                // A malicious Provider supplies forged public bytes. The
                // circuit must use only its credential span and Hub's template.
                let forged = vec![b's'; plaintext.len()];
                let ranges = [3..9];
                let ct_0 = leader
                    .apply_selective_keystream(&mut vm_0, nonce.clone(), &forged, &ranges)
                    .unwrap();
                let ct_1 = follower
                    .apply_selective_keystream(&mut vm_1, nonce.clone(), &plaintext, &ranges)
                    .unwrap();
                plaintext[3..9].fill(b's');
                let ct_0 = vm_0.decode(ct_0).unwrap();
                let ct_1 = vm_1.decode(ct_1).unwrap();
                run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;
                (ct_0.await.unwrap(), ct_1.await.unwrap())
            } else {
                let stream_0 = leader
                    .take_keystream(&mut vm_0, nonce.clone(), plaintext.len())
                    .unwrap();
                let stream_1 = follower
                    .take_keystream(&mut vm_1, nonce.clone(), plaintext.len())
                    .unwrap();
                let stream_0 = vm_0.decode(stream_0).unwrap();
                let stream_1 = vm_1.decode(stream_1).unwrap();
                run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;
                let xor = |stream: Vec<u8>| {
                    stream
                        .into_iter()
                        .zip(&plaintext)
                        .map(|(a, b)| a ^ b)
                        .collect::<Vec<_>>()
                };
                (xor(stream_0.await.unwrap()), xor(stream_1.await.unwrap()))
            };
            assert_eq!(ct_0, ct_1);
            let aad = (sequence as u64).to_be_bytes().to_vec();
            let (expected_ct, expected_tag) = expected(&key, &iv, &nonce, &plaintext, &aad);
            assert_eq!(ct_0, expected_ct);
            let data = || {
                vec![TagData {
                    explicit_nonce: nonce.clone(),
                    aad: aad.clone(),
                }]
            };
            let tags_0 = leader
                .compute_tags(&mut vm_0, vec![async move { Ok(ct_0) }], data())
                .unwrap();
            let tags_1 = follower
                .compute_tags(&mut vm_1, vec![async move { Ok(ct_1) }], data())
                .unwrap();
            // J0 shares were computed during warming: tagging needs no VM work.
            assert!(!vm_0.wants_execute() && !vm_1.wants_execute());
            assert!(!vm_0.wants_flush() && !vm_1.wants_flush());
            let ((tags, _), (hidden_tags, _)) =
                tokio::try_join!(tags_0.run(&mut ctx_0), tags_1.run(&mut ctx_1)).unwrap();
            assert_eq!(tags.unwrap(), vec![expected_tag.clone()]);
            assert!(hidden_tags.is_none());
            let mut full_nonce = [0u8; 12];
            full_nonce[..4].copy_from_slice(&iv);
            full_nonce[4..].copy_from_slice(&nonce);
            let aes = Aes128Gcm::new(&key.into());
            let mut corrupt = expected_ct.clone();
            corrupt[0] ^= 1;
            assert!(
                aes.decrypt_in_place_detached(
                    &full_nonce.into(),
                    &aad,
                    &mut corrupt,
                    expected_tag.as_slice().into()
                )
                .is_err()
            );
            let mut replayed = expected_ct.clone();
            let wrong_sequence = ((sequence + 1) as u64).to_be_bytes();
            assert!(
                aes.decrypt_in_place_detached(
                    &full_nonce.into(),
                    &wrong_sequence,
                    &mut replayed,
                    expected_tag.as_slice().into()
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn warm_record_replay_exhaustion_and_tag_mismatch_fail_closed() {
        for failure in ["nonce", "length", "tag", "early_tag", "exhaustion"] {
            let ((mut vm_0, vars_0), (_, vars_1)) = create_vm([42; 16], [0; 4]);
            let (mut leader, _) = create_pair(vars_0, vars_1);
            leader.alloc(&mut vm_0, 3, 96).unwrap();
            leader.precompute_client(&mut vm_0, 64).unwrap();
            let warm = leader.warm_client.as_mut().unwrap();
            match failure {
                "nonce" => {
                    warm.take(0u64.to_be_bytes(), 16).unwrap();
                    assert!(warm.take(0u64.to_be_bytes(), 16).is_err());
                }
                "length" => assert!(warm.take(0u64.to_be_bytes(), 17).is_err()),
                "tag" => {
                    warm.take(0u64.to_be_bytes(), 16).unwrap();
                    assert!(warm.tag(1u64.to_be_bytes()).is_err());
                }
                "early_tag" => assert!(warm.tag(0u64.to_be_bytes()).is_err()),
                "exhaustion" => {
                    for (seq, len) in [16, 64, 2].into_iter().enumerate() {
                        warm.take((seq as u64).to_be_bytes(), len).unwrap();
                        warm.tag((seq as u64).to_be_bytes()).unwrap();
                    }
                    assert!(warm.take(3u64.to_be_bytes(), 1).is_err());
                }
                _ => unreachable!(),
            }
            assert!(
                warm.take(1u64.to_be_bytes(), 16).is_err(),
                "{failure} allowed retry"
            );
            assert!(
                warm.tag(0u64.to_be_bytes()).is_err(),
                "{failure} allowed tag"
            );
        }
    }

    #[test]
    fn selective_ranges_must_be_sorted_bounded_and_non_overlapping() {
        assert!(validate_leader_ranges(32, &[8..16]).is_ok());
        assert!(validate_leader_ranges(32, &[]).is_err());
        assert!(validate_leader_ranges(32, &[8..8]).is_err());
        assert!(validate_leader_ranges(32, &[16..24, 8..12]).is_err());
        assert!(validate_leader_ranges(32, &[8..20, 16..24]).is_err());
        assert!(validate_leader_ranges(32, &[24..33]).is_err());
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_decrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (ct, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);

            let (ct_0, msg_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), ct.len())
                .unwrap();
            let (ct_1, msg_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), ct.len())
                .unwrap();

            vm_0.assign(ct_0, ct.clone()).unwrap();
            vm_0.commit(ct_0).unwrap();

            vm_1.commit(ct_1).unwrap();

            let msg_0 = vm_0.decode(msg_0).unwrap();
            let msg_1 = vm_1.decode(msg_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let msg_0 = msg_0.await.unwrap();
            let msg_1 = msg_1.await.unwrap();

            assert_eq!(&msg_0, msg);
            assert_eq!(&msg_1, msg);
        }
    }

    fn create_vm(key: [u8; 16], iv: [u8; 4]) -> ((impl Vm<Binary>, Vars), (impl Vm<Binary>, Vars)) {
        let mut vm_0 = IdealVm::new();
        let mut vm_1 = IdealVm::new();

        let key_ref_0 = vm_0.alloc::<Array<U8, 16>>().unwrap();
        vm_0.mark_public(key_ref_0).unwrap();
        vm_0.assign(key_ref_0, key).unwrap();
        vm_0.commit(key_ref_0).unwrap();

        let key_ref_1 = vm_1.alloc::<Array<U8, 16>>().unwrap();
        vm_1.mark_public(key_ref_1).unwrap();
        vm_1.assign(key_ref_1, key).unwrap();
        vm_1.commit(key_ref_1).unwrap();

        let iv_ref_0 = vm_0.alloc::<Array<U8, 4>>().unwrap();
        vm_0.mark_public(iv_ref_0).unwrap();
        vm_0.assign(iv_ref_0, iv).unwrap();
        vm_0.commit(iv_ref_0).unwrap();

        let iv_ref_1 = vm_1.alloc::<Array<U8, 4>>().unwrap();
        vm_1.mark_public(iv_ref_1).unwrap();
        vm_1.assign(iv_ref_1, iv).unwrap();
        vm_1.commit(iv_ref_1).unwrap();

        (
            (
                vm_0,
                Vars {
                    key: key_ref_0,
                    iv: iv_ref_0,
                },
            ),
            (
                vm_1,
                Vars {
                    key: key_ref_1,
                    iv: iv_ref_1,
                },
            ),
        )
    }

    fn create_pair(vars_0: Vars, vars_1: Vars) -> (MpcAesGcm, MpcAesGcm) {
        let mut rng = StdRng::seed_from_u64(0);
        let (c_0, c_1) = ideal_share_convert(Block::random(&mut rng));
        let mut leader = MpcAesGcm::new(c_0, Role::Leader);
        let mut follower = MpcAesGcm::new(c_1, Role::Follower);

        leader.set_key(vars_0.key);
        leader.set_iv(vars_0.iv);

        follower.set_key(vars_1.key);
        follower.set_iv(vars_1.iv);

        (leader, follower)
    }

    async fn run_vms(
        vm_0: &mut (dyn Vm<Binary> + Send),
        ctx_0: &mut Context,
        vm_1: &mut (dyn Vm<Binary> + Send),
        ctx_1: &mut Context,
    ) {
        tokio::join!(
            async {
                vm_0.execute_all(ctx_0).await.unwrap();
            },
            async {
                vm_1.execute_all(ctx_1).await.unwrap();
            }
        );
    }

    fn expected(
        key: &[u8],
        iv: &[u8],
        explicit_nonce: &[u8],
        msg: &[u8],
        aad: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key: [u8; 16] = key.try_into().unwrap();
        let aes = Aes128Gcm::new(&key.into());

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(iv);
        nonce[4..].copy_from_slice(explicit_nonce);

        let mut payload = msg.to_vec();
        let tag = aes
            .encrypt_in_place_detached(&nonce.into(), aad, &mut payload)
            .unwrap();

        (payload, tag.to_vec())
    }
}
