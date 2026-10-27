//! Cumulative Provider upstream-delivery acknowledgements.

/// Fixed delivery acknowledgement payload size.
pub const DELIVERY_ACK_PAYLOAD_SIZE: usize = 8 + 32;

/// A cumulative byte count and SHA-256 prefix digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryAck {
    /// Total upstream bytes written by the Provider relay.
    pub bytes: u64,
    /// SHA-256 digest of exactly the first `bytes` upstream bytes.
    pub sha256: [u8; 32],
}

impl DeliveryAck {
    /// Encodes the acknowledgement as its fixed-width wire payload.
    pub fn encode(self) -> Result<[u8; DELIVERY_ACK_PAYLOAD_SIZE], DeliveryAckError> {
        if self.bytes == 0 {
            return Err(DeliveryAckError);
        }
        let mut payload = [0u8; DELIVERY_ACK_PAYLOAD_SIZE];
        payload[..8].copy_from_slice(&self.bytes.to_be_bytes());
        payload[8..].copy_from_slice(&self.sha256);
        Ok(payload)
    }

    /// Decodes and strictly validates a fixed-width wire payload.
    pub fn decode(payload: &[u8]) -> Result<Self, DeliveryAckError> {
        if payload.len() != DELIVERY_ACK_PAYLOAD_SIZE {
            return Err(DeliveryAckError);
        }
        let bytes = u64::from_be_bytes(payload[..8].try_into().expect("fixed slice"));
        if bytes == 0 {
            return Err(DeliveryAckError);
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&payload[8..]);
        Ok(Self { bytes, sha256 })
    }
}

/// Invalid delivery acknowledgement payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid delivery acknowledgement")]
pub struct DeliveryAckError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_reject_invalid_payloads() {
        let expected = DeliveryAck {
            bytes: 1234,
            sha256: [0x5a; 32],
        };
        assert_eq!(
            DeliveryAck::decode(&expected.encode().unwrap()),
            Ok(expected)
        );
        assert!(DeliveryAck::decode(&[]).is_err());
        assert!(DeliveryAck::decode(&[0u8; DELIVERY_ACK_PAYLOAD_SIZE]).is_err());
    }
}
