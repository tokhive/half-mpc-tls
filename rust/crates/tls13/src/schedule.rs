//! RFC 8446 section 7.1, SHA-256 only. Secret values remain VM references.
use crate::{Result, fail};
use mpz_circuits::circuits::xor;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{
    Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, Vm, prelude::*};
use sha2::{Digest, Sha256 as LocalSha256};
use std::sync::Arc;

pub type Secret = Array<U8, 32>;

pub fn public(vm: &mut dyn Vm<Binary>, bytes: &[u8]) -> Result<Vector<U8>> {
    let value = vm.alloc_vec::<U8>(bytes.len())?;
    vm.mark_public(value)?;
    vm.assign(value, bytes.to_vec())?;
    vm.commit(value)?;
    Ok(value)
}

pub fn xor_bytes(vm: &mut dyn Vm<Binary>, a: Vector<U8>, b: Vector<U8>) -> Result<Vector<U8>> {
    if a.len() != b.len() {
        return Err(fail("XOR length mismatch"));
    }
    Ok(vm.call(
        Call::builder(Arc::new(xor(a.len() * 8)))
            .arg(a)
            .arg(b)
            .build()?,
    )?)
}

pub fn hmac(vm: &mut dyn Vm<Binary>, key: Secret, input: &[Vector<U8>]) -> Result<Secret> {
    let inner_pad = public(vm, &[0x36; 32])?;
    let outer_pad = public(vm, &[0x5c; 32])?;
    let inner_key = xor_bytes(vm, key.into(), inner_pad)?;
    let outer_key = xor_bytes(vm, key.into(), outer_pad)?;
    let mut inner = Sha256::new();
    inner.update(&inner_key);
    inner.update(&inner_pad);
    for data in input {
        inner.update(data);
    }
    inner.compress(vm)?;
    let digest = inner.finalize(vm)?;
    let mut outer = Sha256::new();
    outer.update(&outer_key);
    outer.update(&outer_pad);
    outer.update(&digest.into());
    outer.compress(vm)?;
    Ok(outer.finalize(vm)?)
}

pub fn label_bytes(label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>> {
    if len == 0 || len > 32 || label.len() + 6 > 255 || context.len() > 255 {
        return Err(fail("invalid HKDF label"));
    }
    let mut info = Vec::with_capacity(10 + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((label.len() + 6) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info.push(1);
    Ok(info)
}

pub fn expand(
    vm: &mut dyn Vm<Binary>,
    secret: Secret,
    label: &[u8],
    context: &[u8],
) -> Result<Secret> {
    let info = public(vm, &label_bytes(label, context, 32)?)?;
    hmac(vm, secret, &[info])
}

pub fn key_iv(vm: &mut dyn Vm<Binary>, secret: Secret) -> Result<(Array<U8, 16>, Array<U8, 12>)> {
    let info = public(vm, &label_bytes(b"key", &[], 16)?)?;
    let key = hmac(vm, secret, &[info])?;
    let info = public(vm, &label_bytes(b"iv", &[], 12)?)?;
    let iv = hmac(vm, secret, &[info])?;
    Ok((key.get::<16>(0).unwrap(), iv.get::<12>(0).unwrap()))
}

pub struct Handshake {
    pub client: Secret,
    pub server: Secret,
    pub master: Secret,
}

pub fn handshake(
    vm: &mut dyn Vm<Binary>,
    ecdhe: Secret,
    hello_hash: &[u8; 32],
) -> Result<Handshake> {
    // No PSK, early data or resumption. Early secret and its derived value are public.
    let early = local_hmac(&[0; 32], &[0; 32]);
    let empty: [u8; 32] = LocalSha256::digest([]).into();
    let derived = local_expand(&early, b"derived", &empty, 32)?;
    let derived: Secret = public(vm, &derived)?.try_into()?;
    let hs = hmac(vm, derived, &[ecdhe.into()])?;
    let client = expand(vm, hs, b"c hs traffic", hello_hash)?;
    let server = expand(vm, hs, b"s hs traffic", hello_hash)?;
    let derived = expand(vm, hs, b"derived", &empty)?;
    let zero = public(vm, &[0; 32])?;
    let master = hmac(vm, derived, &[zero])?;
    Ok(Handshake {
        client,
        server,
        master,
    })
}

#[cfg(test)]
pub fn finished(vm: &mut dyn Vm<Binary>, traffic: Secret, hash: &[u8; 32]) -> Result<Secret> {
    let key = expand(vm, traffic, b"finished", &[])?;
    let hash = public(vm, hash)?;
    hmac(vm, key, &[hash])
}

pub fn local_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<LocalSha256>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
pub fn local_expand(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    Ok(local_hmac(secret, &label_bytes(label, context, len)?)[..len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;

    #[tokio::test]
    async fn shared_hkdf_matches_independent_rfc_schedule() {
        let (ca, cb) = test_st_context(128);
        let run = |mut vm: IdealVm, mut ctx: mpz_common::Context| async move {
            let secret: Secret = public(&mut vm, &[7; 32]).unwrap().try_into().unwrap();
            let hs = handshake(&mut vm, secret, &[8; 32]).unwrap();
            let app = expand(&mut vm, hs.master, b"c ap traffic", &[9; 32]).unwrap();
            let next = expand(&mut vm, app, b"traffic upd", &[]).unwrap();
            let (key, iv) = key_iv(&mut vm, next).unwrap();
            let sf = finished(&mut vm, hs.server, &[10; 32]).unwrap();
            let mut key = vm.decode(key).unwrap();
            let mut iv = vm.decode(iv).unwrap();
            let mut sf = vm.decode(sf).unwrap();
            vm.execute_all(&mut ctx).await.unwrap();
            (
                key.try_recv().unwrap().unwrap(),
                iv.try_recv().unwrap().unwrap(),
                sf.try_recv().unwrap().unwrap(),
            )
        };
        let (a, b) = tokio::join!(run(IdealVm::new(), ca), run(IdealVm::new(), cb));
        assert_eq!(a, b);
        let empty: [u8; 32] = LocalSha256::digest([]).into();
        let early = local_hmac(&[0; 32], &[0; 32]);
        let derived = local_expand(&early, b"derived", &empty, 32).unwrap();
        let hs = local_hmac(&derived, &[7; 32]);
        let shs: [u8; 32] = local_expand(&hs, b"s hs traffic", &[8; 32], 32)
            .unwrap()
            .try_into()
            .unwrap();
        let master = local_hmac(
            &local_expand(&hs, b"derived", &empty, 32).unwrap(),
            &[0; 32],
        );
        let app: [u8; 32] = local_expand(&master, b"c ap traffic", &[9; 32], 32)
            .unwrap()
            .try_into()
            .unwrap();
        let next: [u8; 32] = local_expand(&app, b"traffic upd", &[], 32)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            a.0.as_slice(),
            local_expand(&next, b"key", &[], 16).unwrap()
        );
        assert_eq!(a.1.as_slice(), local_expand(&next, b"iv", &[], 12).unwrap());
        assert_eq!(
            a.2,
            local_hmac(
                &local_expand(&shs, b"finished", &[], 32).unwrap(),
                &[10; 32]
            )
        );
    }
    #[tokio::test]
    async fn rfc8448_client_handshake_traffic_secret() {
        // RFC 8448 section 3: independently published HKDF-Expand-Label vector.
        fn hex(s: &str) -> Vec<u8> {
            s.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect()
        }
        let secret = hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
        let hash = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let expected = hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
        let (a, b) = test_st_context(128);
        let run = |mut ctx: mpz_common::Context| {
            let secret = secret.clone();
            let hash = hash.clone();
            async move {
                let mut vm = IdealVm::new();
                let input: Secret = public(&mut vm, &secret).unwrap().try_into().unwrap();
                let output = expand(&mut vm, input, b"c hs traffic", &hash).unwrap();
                let mut future = vm.decode(output).unwrap();
                vm.execute_all(&mut ctx).await.unwrap();
                future.try_recv().unwrap().unwrap()
            }
        };
        let (x, y) = tokio::join!(run(a), run(b));
        assert_eq!(x, y);
        assert_eq!(x.as_slice(), expected);
    }
}
