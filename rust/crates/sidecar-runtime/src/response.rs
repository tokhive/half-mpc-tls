use aes_gcm::{Aes128Gcm, NewAead, aead::AeadMutInPlace};
use mpc_tls::{ServerRecord, ServerRecordReceiver};
use thiserror::Error;
use tokenhive_key_release::ServerTrafficKeys;
use tokio::io::{AsyncWriteExt, DuplexStream};
use zeroize::Zeroizing;

const TLS12_VERSION: u16 = 0x0303;
const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const CLOSE_NOTIFY: [u8; 2] = [1, 0];

#[derive(Debug, Error)]
pub(crate) enum ResponseError {
    #[error("invalid encrypted server record")]
    InvalidRecord,
    #[error("server record authentication failed")]
    Authentication,
    #[error("unsupported post-handshake TLS record")]
    UnsupportedRecord,
    #[error("upstream TLS alert")]
    Alert,
    #[error("response channel failed")]
    Output,
}

enum PlainRecord {
    Application(Zeroizing<Vec<u8>>),
    CloseNotify,
}

struct ServerRecordDecryptor {
    write_key: Zeroizing<[u8; 16]>,
    fixed_iv: Zeroizing<[u8; 4]>,
    next_sequence: u64,
}

impl ServerRecordDecryptor {
    fn new(keys: ServerTrafficKeys) -> Self {
        Self::from_key_parts(*keys.write_key(), *keys.fixed_iv())
    }

    fn from_key_parts(write_key: [u8; 16], fixed_iv: [u8; 4]) -> Self {
        // The encrypted-record tap starts after the server Finished record,
        // which consumes server record sequence number zero.
        Self {
            write_key: Zeroizing::new(write_key),
            fixed_iv: Zeroizing::new(fixed_iv),
            next_sequence: 1,
        }
    }

    fn decrypt(&mut self, record: ServerRecord) -> Result<PlainRecord, ResponseError> {
        self.decrypt_parts(
            record.sequence(),
            record.content_type(),
            record.protocol_version(),
            record.explicit_nonce(),
            record.ciphertext(),
            record.tag(),
        )
    }

    fn decrypt_parts(
        &mut self,
        sequence: u64,
        content_type: u8,
        protocol_version: u16,
        explicit_nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<PlainRecord, ResponseError> {
        let ciphertext_len: u16 = ciphertext
            .len()
            .try_into()
            .map_err(|_| ResponseError::InvalidRecord)?;
        if sequence != self.next_sequence
            || protocol_version != TLS12_VERSION
            || explicit_nonce.len() != 8
            || tag.len() != 16
        {
            return Err(ResponseError::InvalidRecord);
        }

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed_iv[..]);
        nonce[4..].copy_from_slice(explicit_nonce);

        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&sequence.to_be_bytes());
        aad[8] = content_type;
        aad[9..11].copy_from_slice(&protocol_version.to_be_bytes());
        aad[11..].copy_from_slice(&ciphertext_len.to_be_bytes());

        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        let mut cipher = Aes128Gcm::new((&*self.write_key).into());
        cipher
            .decrypt_in_place_detached((&nonce).into(), &aad, &mut plaintext, tag.into())
            .map_err(|_| ResponseError::Authentication)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ResponseError::InvalidRecord)?;

        match content_type {
            APPLICATION_DATA => Ok(PlainRecord::Application(plaintext)),
            ALERT if plaintext.as_slice() == CLOSE_NOTIFY => Ok(PlainRecord::CloseNotify),
            ALERT => Err(ResponseError::Alert),
            CHANGE_CIPHER_SPEC | HANDSHAKE => Err(ResponseError::UnsupportedRecord),
            _ => Err(ResponseError::InvalidRecord),
        }
    }
}

pub(crate) async fn pump_authenticated_response(
    mut records: ServerRecordReceiver,
    keys: ServerTrafficKeys,
    mut output: DuplexStream,
) -> Result<(), ResponseError> {
    let mut decryptor = ServerRecordDecryptor::new(keys);
    while let Some(record) = records.recv().await {
        match decryptor.decrypt(record)? {
            PlainRecord::Application(plaintext) => output
                .write_all(&plaintext)
                .await
                .map_err(|_| ResponseError::Output)?,
            PlainRecord::CloseNotify => break,
        }
    }
    output.shutdown().await.map_err(|_| ResponseError::Output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_record(
        key: &[u8; 16],
        fixed_iv: &[u8; 4],
        sequence: u64,
        plaintext: &[u8],
    ) -> ([u8; 8], Vec<u8>, Vec<u8>) {
        let explicit_nonce = sequence.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(fixed_iv);
        nonce[4..].copy_from_slice(&explicit_nonce);
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&sequence.to_be_bytes());
        aad[8] = APPLICATION_DATA;
        aad[9..11].copy_from_slice(&TLS12_VERSION.to_be_bytes());
        aad[11..].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
        let mut cipher = Aes128Gcm::new(key.into());
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, &mut ciphertext)
            .unwrap();
        (explicit_nonce, ciphertext, tag.to_vec())
    }

    #[test]
    fn rejects_tamper_without_consuming_sequence_and_rejects_replay() {
        let key = [0x42; 16];
        let fixed_iv = [0x24; 4];
        let (nonce, ciphertext, tag) = encrypt_record(&key, &fixed_iv, 1, b"authenticated");
        let mut decryptor = ServerRecordDecryptor::from_key_parts(key, fixed_iv);

        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 1;
        assert!(matches!(
            decryptor.decrypt_parts(
                1,
                APPLICATION_DATA,
                TLS12_VERSION,
                &nonce,
                &ciphertext,
                &bad_tag,
            ),
            Err(ResponseError::Authentication)
        ));

        let record = decryptor
            .decrypt_parts(
                1,
                APPLICATION_DATA,
                TLS12_VERSION,
                &nonce,
                &ciphertext,
                &tag,
            )
            .unwrap();
        let PlainRecord::Application(plaintext) = record else {
            panic!("application record changed type")
        };
        assert_eq!(plaintext.as_slice(), b"authenticated");

        assert!(matches!(
            decryptor.decrypt_parts(
                1,
                APPLICATION_DATA,
                TLS12_VERSION,
                &nonce,
                &ciphertext,
                &tag,
            ),
            Err(ResponseError::InvalidRecord)
        ));
    }
}
