//! TLS 1.3 records: implicit sequence nonce, inner type, outer AAD and epoch reset.
use crate::{Result, fail, mpc::Party, schedule};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, NewAead, Payload},
};
use mpz_circuits::{AES128_KS, AES128_POST_KS, CircuitBuilder};
use mpz_memory_core::{
    Array, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, Vm, prelude::*};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const MAX_PLAIN: usize = 16384;
pub const MAX_CIPHER: usize = 16640;
pub const PREFIX_CAPACITY: usize = 1024;

pub struct Traffic {
    secret: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 16]>,
    iv: Zeroizing<[u8; 12]>,
    seq: u64,
    failed: bool,
}
impl Traffic {
    pub fn new(secret: [u8; 32]) -> Result<Self> {
        let secret = Zeroizing::new(secret);
        let key = Zeroizing::new(
            schedule::local_expand(&secret, b"key", &[], 16)?
                .try_into()
                .map_err(|_| fail("key size"))?,
        );
        let iv = Zeroizing::new(
            schedule::local_expand(&secret, b"iv", &[], 12)?
                .try_into()
                .map_err(|_| fail("IV size"))?,
        );
        Ok(Self {
            secret,
            key,
            iv,
            seq: 0,
            failed: false,
        })
    }
    fn nonce(&mut self) -> Result<[u8; 12]> {
        if self.failed || self.seq == u64::MAX {
            self.failed = true;
            return Err(fail("record sequence exhausted or failed"));
        }
        let mut nonce = *self.iv;
        for (a, b) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *a ^= b;
        }
        self.seq += 1;
        Ok(nonce)
    }
    pub fn seal(&mut self, kind: u8, plain: &[u8]) -> Result<Vec<u8>> {
        if plain.len() > MAX_PLAIN || !matches!(kind, 21..=23) {
            self.failed = true;
            return Err(fail("invalid TLS plaintext"));
        }
        let nonce = self.nonce()?;
        let mut inner = Zeroizing::new(plain.to_vec());
        inner.push(kind);
        let header = header(inner.len() + 16)?;
        let cipher = Aes128Gcm::new_from_slice(self.key.as_ref()).map_err(|_| fail("AES key"))?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &inner,
                    aad: &header,
                },
            )
            .map_err(|_| fail("TLS encrypt failed"))?;
        Ok([header.as_slice(), &sealed].concat())
    }
    pub fn open(&mut self, record: &[u8]) -> Result<(u8, Zeroizing<Vec<u8>>)> {
        // Poison before parsing or authenticating. Any error permanently destroys use.
        let nonce = self.nonce()?;
        self.failed = true;
        if record.len() < 22
            || record[..3] != [23, 3, 3]
            || usize::from(u16::from_be_bytes([record[3], record[4]])) + 5 != record.len()
            || record.len() > MAX_CIPHER + 5
        {
            return Err(fail("invalid TLSCiphertext"));
        }
        let cipher = Aes128Gcm::new_from_slice(self.key.as_ref()).map_err(|_| fail("AES key"))?;
        let mut plain = Zeroizing::new(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &record[5..],
                        aad: &record[..5],
                    },
                )
                .map_err(|_| fail("TLS record authentication failed"))?,
        );
        while plain.last() == Some(&0) {
            plain.pop();
        }
        let kind = plain.pop().ok_or_else(|| fail("missing TLS inner type"))?;
        if !matches!(kind, 21..=23) || plain.len() > MAX_PLAIN {
            return Err(fail("invalid TLS inner plaintext"));
        }
        self.failed = false;
        Ok((kind, plain))
    }
    pub fn update(&mut self) -> Result<()> {
        if self.failed {
            return Err(fail("failed traffic epoch"));
        }
        let next = schedule::local_expand(&self.secret, b"traffic upd", &[], 32)?;
        *self = Self::new(next.try_into().map_err(|_| fail("traffic secret size"))?)?;
        Ok(())
    }
}

pub fn header(len: usize) -> Result<[u8; 5]> {
    if len > MAX_CIPHER {
        return Err(fail("TLS record too large"));
    }
    let len = (len as u16).to_be_bytes();
    Ok([23, 3, 3, len[0], len[1]])
}

/// Precomputed old-epoch AES. No credential keystream is ever decoded.
pub struct WarmPrefix {
    h: Array<U8, 16>,
    masks: [Array<U8, 16>; 2],
    prefix: Vec<Array<U8, 16>>,
    update: Array<U8, 16>,
    used: bool,
}
impl WarmPrefix {
    pub fn new(vm: &mut dyn Vm<Binary>, secret: schedule::Secret) -> Result<Self> {
        let (key, iv) = schedule::key_iv(vm, secret)?;
        let ks: Array<U8, 176> = vm.call(Call::builder(AES128_KS.clone()).arg(key).build()?)?;
        let zero = schedule::public(vm, &[0; 16])?;
        let h = vm.call(
            Call::builder(AES128_POST_KS.clone())
                .arg(ks)
                .arg(zero)
                .build()?,
        )?;
        let mut block = |sequence: u64, counter: u32| -> Result<Array<U8, 16>> {
            let mut seq = [0; 12];
            seq[4..].copy_from_slice(&sequence.to_be_bytes());
            let seq = schedule::public(vm, &seq)?;
            let nonce = schedule::xor_bytes(vm, iv.into(), seq)?;
            let counter = schedule::public(vm, &counter.to_be_bytes())?;
            Ok(vm.call(
                Call::builder(AES128_POST_KS.clone())
                    .arg(ks)
                    .arg(nonce)
                    .arg(counter)
                    .build()?,
            )?)
        };
        let masks = [block(0, 1)?, block(1, 1)?];
        let prefix = (0..PREFIX_CAPACITY.div_ceil(16))
            .map(|i| block(0, i as u32 + 2))
            .collect::<Result<Vec<_>>>()?;
        let update = block(1, 2)?;
        Ok(Self {
            h,
            masks,
            prefix,
            update,
            used: false,
        })
    }
    pub async fn encrypt(
        &mut self,
        party: &mut Party,
        public: &[u8],
        credential: Option<&[u8]>,
        span: std::ops::Range<usize>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if std::mem::replace(&mut self.used, true)
            || public.is_empty()
            || public.len() + 1 > PREFIX_CAPACITY
            || span.start >= span.end
            || span.end > public.len()
        {
            return Err(fail("invalid or reused credential prefix"));
        }
        if public[span.clone()].iter().any(|b| *b != 0) {
            return Err(fail("credential slot must be zero"));
        }
        let vm = party.vm.vm();
        let mut hub_plain = Zeroizing::new(public.to_vec());
        hub_plain.push(23);
        let mut provider_plain = Zeroizing::new(vec![0; hub_plain.len()]);
        if party.provider {
            let credential = credential.ok_or_else(|| fail("missing Provider credential"))?;
            if credential.len() != span.len() {
                return Err(fail("credential size mismatch"));
            }
            provider_plain[span.clone()].copy_from_slice(credential);
        } else if credential.is_some() {
            return Err(fail("Hub cannot supply credential"));
        }
        let (a, b) = party.prefix_inputs;
        let plain_len = hub_plain.len();
        hub_plain.resize(PREFIX_CAPACITY, 0);
        provider_plain.resize(PREFIX_CAPACITY, 0);
        if party.provider {
            vm.assign(b, provider_plain.to_vec())?;
        } else {
            vm.assign(a, hub_plain.to_vec())?;
        }
        vm.commit(a)?;
        vm.commit(b)?;
        // Only the credential slice is wired to Provider inputs. A malicious
        // evaluator cannot modify HTTP headers or the inner content type by
        // assigning nonzero bytes elsewhere in its preallocated input buffer.
        let valid: U8 = vm.call(
            Call::builder(Arc::new(credential_validity(span.len())?))
                .arg(b.get(span.clone()).unwrap())
                .build()?,
        )?;
        let valid = vm.decode(valid)?;
        let plain = credential_prefix(
            vm,
            a.get(0..plain_len).unwrap(),
            b.get(0..plain_len).unwrap(),
            span,
        )?;
        let mut outputs = Vec::new();
        for (index, stream) in self.prefix.iter().enumerate().take(plain_len.div_ceil(16)) {
            let start = index * 16;
            let end = (start + 16).min(plain_len);
            let mut stream: Vector<U8> = (*stream).into();
            stream.truncate(end - start);
            outputs.push(schedule::xor_bytes(
                vm,
                plain.get(start..end).unwrap(),
                stream,
            )?);
        }
        let update = schedule::public(vm, &[24, 0, 0, 1, 0, 22])?;
        let mut stream: Vector<U8> = self.update.into();
        stream.truncate(6);
        let update = schedule::xor_bytes(vm, update, stream)?;
        let mut futures = Vec::new();
        for output in outputs {
            futures.push(party.vm.private_output(output)?);
        }
        let update = party.vm.private_output(update)?;
        let h = party.vm.private_output(self.h)?;
        let mask0 = party.vm.private_output(self.masks[0])?;
        let mask1 = party.vm.private_output(self.masks[1])?;
        party.execute().await?;
        if valid.await? != 0xff {
            return Err(fail("credential contains unsafe HTTP header bytes"));
        }
        let mut cipher = Vec::new();
        for output in futures {
            if let Some(bytes) = output.receive().await? {
                cipher.extend(bytes);
            }
        }
        let update = update.receive().await?;
        let h = h.receive().await?;
        let mask0 = mask0.receive().await?;
        let mask1 = mask1.receive().await?;
        if party.provider {
            return Ok(None);
        }
        let update = update.ok_or_else(|| fail("missing Hub output"))?;
        fn block(value: Option<Vec<u8>>) -> Result<Zeroizing<[u8; 16]>> {
            let value = Zeroizing::new(value.ok_or_else(|| fail("missing Hub output"))?);
            Ok(Zeroizing::new(
                value
                    .as_slice()
                    .try_into()
                    .map_err(|_| fail("output block size"))?,
            ))
        }
        let h = block(h)?;
        let mask0 = block(mask0)?;
        let mask1 = block(mask1)?;
        Ok(Some((
            finish_record(&h, &mask0, &cipher)?,
            finish_record(&h, &mask1, &update)?,
        )))
    }
}
fn credential_validity(len: usize) -> Result<mpz_circuits::Circuit> {
    use mpz_circuits::{Feed, Node};
    fn or(builder: &mut CircuitBuilder, a: Node<Feed>, b: Node<Feed>) -> Node<Feed> {
        let xor = builder.add_xor_gate(a, b);
        let and = builder.add_and_gate(a, b);
        builder.add_xor_gate(xor, and)
    }
    if len == 0 || len > PREFIX_CAPACITY {
        return Err(fail("credential length"));
    }
    let mut builder = CircuitBuilder::new();
    let input = (0..len * 8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    let mut valid = builder.get_const_one();
    for byte in input.as_chunks::<8>().0 {
        let mut lower = byte[0];
        for bit in &byte[1..5] {
            lower = or(&mut builder, lower, *bit);
        }
        let thirty_three = builder.add_and_gate(byte[5], lower);
        let lower_bound = or(&mut builder, byte[6], thirty_three);
        let mut del = byte[0];
        for bit in &byte[1..7] {
            del = builder.add_and_gate(del, *bit);
        }
        let not_del = builder.add_inv_gate(del);
        let ascii = builder.add_inv_gate(byte[7]);
        let allowed = builder.add_and_gate(lower_bound, not_del);
        let allowed = builder.add_and_gate(allowed, ascii);
        valid = builder.add_and_gate(valid, allowed);
    }
    for _ in 0..8 {
        let bit = builder.add_id_gate(valid);
        builder.add_output(bit);
    }
    Ok(builder.build()?)
}

fn credential_prefix(
    vm: &mut dyn Vm<Binary>,
    hub: Vector<U8>,
    provider: Vector<U8>,
    span: std::ops::Range<usize>,
) -> Result<Vector<U8>> {
    if hub.len() != provider.len() || span.start >= span.end || span.end > hub.len() {
        return Err(fail("credential circuit bounds"));
    }
    let mut builder = CircuitBuilder::new();
    let a = (0..hub.len() * 8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    let b = (0..provider.len() * 8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    for (index, (a, b)) in a.into_iter().zip(b).enumerate() {
        let output = builder.add_id_gate(if span.contains(&(index / 8)) { b } else { a });
        builder.add_output(output);
    }
    Ok(vm.call(
        Call::builder(Arc::new(builder.build()?))
            .arg(hub)
            .arg(provider)
            .build()?,
    )?)
}

fn finish_record(h: &[u8; 16], mask: &[u8; 16], cipher: &[u8]) -> Result<Vec<u8>> {
    use ghash::{
        GHash,
        universal_hash::{KeyInit, UniversalHash},
    };
    let header = header(cipher.len() + 16)?;
    let mut hash = GHash::new(h.into());
    hash.update_padded(&header);
    hash.update_padded(cipher);
    let mut lengths = [0; 16];
    lengths[..8].copy_from_slice(&40u64.to_be_bytes());
    lengths[8..].copy_from_slice(&((cipher.len() as u64) * 8).to_be_bytes());
    hash.update(&[lengths.into()]);
    let mut tag = hash.finalize();
    for (a, b) in tag.iter_mut().zip(mask) {
        *a ^= b;
    }
    Ok([header.as_slice(), cipher, tag.as_slice()].concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_resets_nonce_and_rejects_old_epoch() {
        let mut tx = Traffic::new([7; 32]).unwrap();
        let mut rx = Traffic::new([7; 32]).unwrap();
        let a = tx.seal(23, b"credential").unwrap();
        assert_eq!(rx.open(&a).unwrap().1.as_slice(), b"credential");
        tx.update().unwrap();
        rx.update().unwrap();
        let b = tx.seal(23, b"body").unwrap();
        assert_eq!(rx.open(&b).unwrap().1.as_slice(), b"body");
        let mut stale = Traffic::new([7; 32]).unwrap();
        assert!(stale.open(&b).is_err());
        assert!(rx.open(&a).is_err());
        assert!(rx.update().is_err());
    }
    #[test]
    fn corruption_replay_and_wrong_aad_poison_epoch() {
        for offset in [0, 1, 3, 5, 21] {
            let mut tx = Traffic::new([9; 32]).unwrap();
            let mut rx = Traffic::new([9; 32]).unwrap();
            let a = tx.seal(23, b"message").unwrap();
            let mut bad = a.clone();
            bad[offset] ^= 1;
            assert!(rx.open(&bad).is_err());
            assert!(rx.open(&a).is_err());
        }
        let mut tx = Traffic::new([9; 32]).unwrap();
        let mut rx = Traffic::new([9; 32]).unwrap();
        let a = tx.seal(23, b"message").unwrap();
        rx.open(&a).unwrap();
        assert!(rx.open(&a).is_err());
    }
    #[test]
    fn record_size_and_sequence_limits() {
        let mut tx = Traffic::new([4; 32]).unwrap();
        let rec = tx.seal(23, &[8; MAX_PLAIN]).unwrap();
        let mut rx = Traffic::new([4; 32]).unwrap();
        assert_eq!(rx.open(&rec).unwrap().1.len(), MAX_PLAIN);
        assert!(tx.seal(23, &[8; MAX_PLAIN + 1]).is_err());
        let mut tx = Traffic::new([4; 32]).unwrap();
        tx.seq = u64::MAX;
        assert!(tx.seal(23, b"x").is_err());
    }
    #[test]
    fn split_ghash_matches_independent_aead_tag() {
        // AES-128(0^128, 0^128), AES-128(0^128, 0^96 || 1).
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let mask = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        for size in [1, 6, 15, 16, 17, 1024] {
            let plain = vec![23; size];
            let aad = header(size + 16).unwrap();
            let aead = Aes128Gcm::new_from_slice(&[0; 16]).unwrap();
            let sealed = aead
                .encrypt(
                    (&[0; 12]).into(),
                    Payload {
                        msg: &plain,
                        aad: &aad,
                    },
                )
                .unwrap();
            let actual = finish_record(&h, &mask, &sealed[..size]).unwrap();
            assert_eq!(actual, [aad.as_slice(), &sealed].concat());
        }
    }
    #[tokio::test]
    async fn provider_cannot_modify_bytes_outside_credential_span() {
        use mpz_common::context::test_st_context;
        use mpz_ideal_vm::IdealVm;
        let (a, b) = test_st_context(128);
        let run = |mut ctx: mpz_common::Context| async move {
            let mut vm = IdealVm::new();
            let hub = schedule::public(&mut vm, &[0x42; 32]).unwrap();
            let provider = schedule::public(&mut vm, &[0xff; 32]).unwrap();
            let output = credential_prefix(&mut vm, hub, provider, 13..19).unwrap();
            let mut output = vm.decode(output).unwrap();
            vm.execute_all(&mut ctx).await.unwrap();
            output.try_recv().unwrap().unwrap()
        };
        let (x, y) = tokio::join!(run(a), run(b));
        assert_eq!(x, y);
        let mut expected = [0x42; 32];
        expected[13..19].fill(0xff);
        assert_eq!(x, expected);
    }
    #[test]
    fn credential_predicate_rejects_controls_space_and_non_ascii() {
        let circuit = credential_validity(1).unwrap();
        for byte in 0..=255u8 {
            let actual: u8 = mpz_circuits::evaluate!(circuit, byte).unwrap();
            assert_eq!(
                actual,
                if (33..=126).contains(&byte) { 255 } else { 0 },
                "byte {byte}"
            );
        }
        let circuit = credential_validity(4).unwrap();
        let bad: u8 = mpz_circuits::evaluate!(circuit, *b"ab\rc").unwrap();
        assert_eq!(bad, 0);
        let valid: u8 = mpz_circuits::evaluate!(circuit, *b"abcd").unwrap();
        assert_eq!(valid, 255);
    }
}
