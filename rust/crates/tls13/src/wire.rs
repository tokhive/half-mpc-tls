use crate::{Result, fail};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};
use tlsn_core::{
    connection::ServerName,
    webpki::{CertificateDer, RootCertStore, ServerCertVerifier},
};

pub struct Reader<'a> {
    data: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(fail("truncated TLS message"));
        }
        let (a, b) = self.data.split_at(n);
        self.data = b;
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
    pub fn vector8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    pub fn vector16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    pub fn vector24(&mut self) -> Result<&'a [u8]> {
        let n = self.u24()?;
        self.take(n)
    }
    pub fn end(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(fail("trailing TLS data"))
        }
    }
    pub fn empty(&self) -> bool {
        self.data.is_empty()
    }
}
fn v16(data: &[u8]) -> Vec<u8> {
    [(data.len() as u16).to_be_bytes().as_slice(), data].concat()
}
fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
    [kind.to_be_bytes().as_slice(), &v16(data)].concat()
}
pub fn handshake(kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > 1 << 20 {
        return Err(fail("handshake too large"));
    }
    let len = (body.len() as u32).to_be_bytes();
    Ok([&[kind], &len[1..], body].concat())
}
pub fn client_hello(
    name: &str,
    key: &[u8],
    random: [u8; 32],
    session: [u8; 32],
) -> Result<Vec<u8>> {
    let _ = ServerName::Dns(name.try_into()?);
    if key.len() != 65 {
        return Err(fail("unsupported ECDHE share"));
    }
    let names = [&[0], v16(name.as_bytes()).as_slice()].concat();
    let keyshare = [23u16.to_be_bytes().as_slice(), v16(key).as_slice()].concat();
    let exts = [
        ext(0, &v16(&names)),
        ext(10, &[0, 2, 0, 23]),
        ext(13, &[0, 6, 8, 4, 4, 3, 8, 7]),
        ext(43, &[2, 3, 4]),
        ext(51, &v16(&keyshare)),
        ext(
            16,
            &[0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'],
        ),
    ]
    .concat();
    let body = [
        &[3, 3],
        random.as_slice(),
        &[32],
        session.as_slice(),
        &[0, 2, 0x13, 1, 1, 0],
        v16(&exts).as_slice(),
    ]
    .concat();
    handshake(1, &body)
}
pub fn plaintext_record(handshake: &[u8]) -> Result<Vec<u8>> {
    if handshake.len() > 16384 {
        return Err(fail("plaintext record too large"));
    }
    Ok([
        &[22, 3, 1],
        (handshake.len() as u16).to_be_bytes().as_slice(),
        handshake,
    ]
    .concat())
}
fn extensions(data: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut r = Reader::new(data);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while !r.empty() {
        let kind = r.u16()?;
        let bytes = r.vector16()?;
        if !seen.insert(kind) {
            return Err(fail("duplicate TLS extension"));
        }
        out.push((kind, bytes));
    }
    Ok(out)
}
pub fn server_hello(message: &[u8], session: &[u8; 32]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body(message, 2)?);
    if r.take(2)? != [3, 3] {
        return Err(fail("invalid legacy version"));
    }
    let random = r.take(32)?;
    const HRR: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if random == HRR {
        return Err(fail("HelloRetryRequest is not supported"));
    }
    if r.vector8()? != session || r.u16()? != 0x1301 || r.u8()? != 0 {
        return Err(fail("TLS 1.3 negotiation mismatch"));
    }
    let extensions = extensions(r.vector16()?)?;
    r.end()?;
    let mut version = false;
    let mut key = None;
    for (kind, data) in extensions {
        match kind {
            43 => {
                if data != [3, 4] {
                    return Err(fail("TLS downgrade rejected"));
                }
                version = true;
            }
            51 => {
                let mut r = Reader::new(data);
                if r.u16()? != 23 {
                    return Err(fail("unsupported ECDHE group"));
                }
                let bytes = r.vector16()?;
                r.end()?;
                let _ = p256::PublicKey::from_sec1_bytes(bytes)?;
                key = Some(bytes.to_vec());
            }
            _ => return Err(fail("unoffered ServerHello extension")),
        }
    }
    if !version {
        return Err(fail("missing TLS 1.3 selected version"));
    }
    key.ok_or_else(|| fail("missing key share"))
}
pub fn encrypted_extensions(message: &[u8]) -> Result<()> {
    let mut r = Reader::new(body(message, 8)?);
    let list = extensions(r.vector16()?)?;
    r.end()?;
    for (kind, data) in list {
        match kind {
            0 if data.is_empty() => {}
            16 if data == [0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'] => {}
            10 => {
                let mut r = Reader::new(data);
                let groups = r.vector16()?;
                if groups.is_empty() || !groups.len().is_multiple_of(2) {
                    return Err(fail("invalid supported groups"));
                }
                r.end()?;
            }
            _ => return Err(fail("unsupported EncryptedExtensions")),
        }
    }
    Ok(())
}
pub fn certificate(message: &[u8], roots: &RootCertStore, name: &str) -> Result<CertificateDer> {
    let mut r = Reader::new(body(message, 11)?);
    if !r.vector8()?.is_empty() {
        return Err(fail("unexpected certificate context"));
    }
    let mut chain = Reader::new(r.vector24()?);
    r.end()?;
    let mut certificates = Vec::new();
    while !chain.empty() {
        let der = chain.vector24()?;
        if der.is_empty() || der.len() > 65536 || certificates.len() >= 16 {
            return Err(fail("certificate chain limit"));
        }
        certificates.push(CertificateDer(der.to_vec()));
        if !chain.vector16()?.is_empty() {
            return Err(fail("unrequested certificate extension"));
        }
    }
    let leaf = certificates
        .first()
        .ok_or_else(|| fail("empty certificate chain"))?;
    ServerCertVerifier::new(roots)?.verify_server_cert(
        leaf,
        &certificates[1..],
        &ServerName::Dns(name.try_into()?),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    Ok(leaf.clone())
}
pub fn certificate_verify(
    message: &[u8],
    leaf: &CertificateDer,
    transcript: &[u8; 32],
) -> Result<()> {
    let mut r = Reader::new(body(message, 15)?);
    let scheme = r.u16()?;
    let sig = r.vector16()?;
    r.end()?;
    let algorithm = match scheme {
        0x0804 => webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        0x0403 => webpki::ring::ECDSA_P256_SHA256,
        0x0807 => webpki::ring::ED25519,
        _ => return Err(fail("unoffered CertificateVerify algorithm")),
    };
    let signed = [
        &[32u8; 64],
        b"TLS 1.3, server CertificateVerify\0".as_slice(),
        transcript.as_slice(),
    ]
    .concat();
    let der = rustls_pki_types::CertificateDer::from(leaf.0.as_slice());
    webpki::EndEntityCert::try_from(&der)?.verify_signature(algorithm, &signed, sig)?;
    Ok(())
}
pub fn body(message: &[u8], kind: u8) -> Result<&[u8]> {
    let mut r = Reader::new(message);
    if r.u8()? != kind {
        return Err(fail("unexpected handshake message"));
    }
    let body = r.vector24()?;
    r.end()?;
    Ok(body)
}
pub fn hash(transcript: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript).into()
}
#[derive(Default)]
pub struct Handshakes {
    buffer: Vec<u8>,
}
impl Handshakes {
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.buffer.len() + data.len() > 1 << 20 {
            return Err(fail("handshake buffer limit"));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }
    pub fn next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let n = (usize::from(self.buffer[1]) << 16)
            | (usize::from(self.buffer[2]) << 8)
            | usize::from(self.buffer[3]);
        if n > 1 << 20 {
            return Err(fail("handshake length limit"));
        }
        if self.buffer.len() < n + 4 {
            return Ok(None);
        }
        Ok(Some(self.buffer.drain(..n + 4).collect()))
    }
    pub fn empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(version: &[u8], extra: Vec<u8>) -> Vec<u8> {
        let key = p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key();
        let point = p256::EncodedPoint::from(key);
        let share = [
            23u16.to_be_bytes().as_slice(),
            v16(point.as_bytes()).as_slice(),
        ]
        .concat();
        let exts = [ext(43, version), ext(51, &share), extra].concat();
        handshake(
            2,
            &[
                &[3, 3][..],
                &[7; 32],
                &[32],
                &[8; 32],
                &[0x13, 1, 0],
                v16(&exts).as_slice(),
            ]
            .concat(),
        )
        .unwrap()
    }
    #[test]
    fn reject_downgrade_duplicate_extensions_and_truncations() {
        let valid = hello(&[3, 4], vec![]);
        assert!(server_hello(&valid, &[8; 32]).is_ok());
        for n in 0..valid.len() {
            assert!(server_hello(&valid[..n], &[8; 32]).is_err());
        }
        assert!(server_hello(&valid, &[9; 32]).is_err());
        assert!(server_hello(&hello(&[3, 3], vec![]), &[8; 32]).is_err());
        assert!(server_hello(&hello(&[3, 4], ext(43, &[3, 4])), &[8; 32]).is_err());
        assert!(server_hello(&hello(&[3, 4], ext(41, &[0, 0])), &[8; 32]).is_err());
    }
    #[test]
    fn encrypted_extensions_reject_unoffered_protocol_and_early_data() {
        assert!(
            encrypted_extensions(&handshake(8, &v16(&ext(16, b"\x00\x03\x02h2"))).unwrap())
                .is_err()
        );
        assert!(encrypted_extensions(&handshake(8, &v16(&ext(42, &[]))).unwrap()).is_err());
        assert!(encrypted_extensions(&handshake(8, &[0, 0]).unwrap()).is_ok());
    }
    #[test]
    fn handshake_reassembly_and_limits() {
        let message = handshake(20, &[1; 32]).unwrap();
        let mut parser = Handshakes::default();
        for b in &message[..message.len() - 1] {
            parser.feed(&[*b]).unwrap();
            assert!(parser.next().unwrap().is_none());
        }
        parser.feed(&message[message.len() - 1..]).unwrap();
        assert_eq!(parser.next().unwrap().unwrap(), message);
        assert!(parser.empty());
        parser.feed(&[11, 255, 255, 255]).unwrap();
        assert!(parser.next().is_err());
        assert!(Handshakes::default().feed(&vec![0; (1 << 20) + 1]).is_err());
    }
    #[test]
    fn certificate_verify_rejects_forged_signature() {
        let leaf = CertificateDer(tlsn_server_fixture_certs::SERVER_CERT_DER.to_vec());
        let msg = handshake(15, &[&[8, 4], v16(&[0; 256]).as_slice()].concat()).unwrap();
        assert!(certificate_verify(&msg, &leaf, &[0; 32]).is_err());
    }
}
