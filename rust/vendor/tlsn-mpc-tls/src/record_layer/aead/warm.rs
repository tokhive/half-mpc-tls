//! One-use, nonce-bound client AES material. This module never decodes output.
use std::collections::VecDeque;

use cipher::Keystream;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;

use super::{AeadError, Block, Ctr, Nonce};

type Stream = Keystream<Nonce, Ctr, Block>;

struct RecordStream {
    nonce: [u8; 8],
    bytes: usize,
    stream: Stream,
}

pub(super) struct WarmClient {
    records: VecDeque<RecordStream>,
    consumed: u64,
    tagged: u64,
    failed: bool,
}

impl WarmClient {
    pub(super) fn new(
        vm: &mut dyn Vm<Binary>,
        source: &mut Stream,
        capacity: usize,
    ) -> Result<Self, AeadError> {
        if capacity == 0 {
            return Err(AeadError::state("empty warm client capacity"));
        }
        // TLS 1.2 Finished (16 bytes), full application fragments and one alert.
        // The existing allocation includes 32 protocol bytes in addition to capacity.
        let lengths = std::iter::once(16)
            .chain(
                (0..capacity)
                    .step_by(16384)
                    .map(|offset| 16 * (capacity - offset).min(16384).div_ceil(16)),
            )
            .chain(std::iter::once(16));
        let mut records = VecDeque::new();
        for (sequence, bytes) in lengths.enumerate() {
            let nonce = (sequence as u64).to_be_bytes();
            let stream = source.consume(bytes)?;
            let mut counter = 2u32..;
            stream.assign(vm, nonce, || {
                counter.next().expect("bounded record").to_be_bytes()
            })?;
            records.push_back(RecordStream {
                nonce,
                bytes,
                stream,
            });
        }
        Ok(Self {
            records,
            consumed: 0,
            tagged: 0,
            failed: false,
        })
    }

    pub(super) fn take(&mut self, nonce: [u8; 8], bytes: usize) -> Result<Stream, AeadError> {
        if self.failed {
            return Err(AeadError::state("warm client material is invalidated"));
        }
        // Poison before any mutation; errors never permit retries or fallback.
        self.failed = true;
        let mut record = self
            .records
            .pop_front()
            .ok_or_else(|| AeadError::cipher("warm client material exhausted"))?;
        let padded = 16 * bytes.div_ceil(16);
        if nonce != record.nonce || bytes == 0 || padded > record.bytes {
            return Err(AeadError::cipher("warm client nonce or length mismatch"));
        }
        // consume() removes the tail. Burn the unused suffix first so the
        // returned prefix always starts at CTR=2, including short final records.
        if padded < record.bytes {
            let _unused = record.stream.consume(record.bytes - padded)?;
        }
        self.consumed += 1;
        self.failed = false;
        Ok(record.stream)
    }

    pub(super) fn tag(&mut self, nonce: [u8; 8]) -> Result<(), AeadError> {
        if self.failed || nonce != self.tagged.to_be_bytes() || self.tagged >= self.consumed {
            self.failed = true;
            return Err(AeadError::cipher(
                "warm client tag does not match consumed record",
            ));
        }
        self.tagged += 1;
        Ok(())
    }
}

pub(super) fn take_stream(
    vm: &mut dyn Vm<Binary>,
    source: &mut Stream,
    warm: &mut Option<WarmClient>,
    nonce: [u8; 8],
    bytes: usize,
) -> Result<Stream, AeadError> {
    if let Some(warm) = warm {
        return warm.take(nonce, bytes);
    }
    let stream = source.consume(bytes)?;
    let mut counter = 2u32..;
    stream.assign(vm, nonce, || {
        counter.next().expect("bounded record").to_be_bytes()
    })?;
    Ok(stream)
}
