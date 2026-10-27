//! Bounded binary framing shared with the Go control-plane implementation.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: u32 = 0x5448_5631;
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 28;

/// Maximum payload for control frames.
pub const MAX_PAYLOAD_SIZE: usize = 1 << 20;
/// Maximum payload for raw data and sidecar stream frames.
pub const MAX_DATA_FRAME_SIZE: usize = 64 << 10;

/// Binary frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Opens an upstream tunnel stream.
    Open = 1,
    /// Confirms an upstream tunnel stream.
    Opened = 2,
    /// Carries upstream tunnel bytes.
    Data = 3,
    /// Reports stream EOF.
    Eof = 4,
    /// Closes a stream.
    Close = 5,
    /// Reports a protocol or operation error.
    Error = 6,
    /// Liveness request.
    Ping = 7,
    /// Liveness response.
    Pong = 8,
    /// Starts a local sidecar role/version handshake.
    SidecarHello = 9,
    /// Confirms a local sidecar role/version handshake.
    SidecarHelloAck = 10,
    /// Starts a sidecar operation.
    SidecarCommand = 11,
    /// Completes a sidecar operation.
    SidecarResult = 12,
    /// Carries bounded sidecar stream bytes.
    SidecarStream = 13,
    /// Completes a sidecar stream.
    SidecarStreamEnd = 14,
    /// Cancels an in-flight sidecar operation.
    SidecarCancel = 15,
    /// Confirms cumulative tunnel bytes written to the Provider's upstream TCP socket.
    DeliveryAck = 16,
}

impl FrameType {
    fn max_payload_size(self) -> usize {
        match self {
            Self::Data | Self::SidecarStream => MAX_DATA_FRAME_SIZE,
            _ => MAX_PAYLOAD_SIZE,
        }
    }
}

impl TryFrom<u8> for FrameType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, WireError> {
        Ok(match value {
            1 => Self::Open,
            2 => Self::Opened,
            3 => Self::Data,
            4 => Self::Eof,
            5 => Self::Close,
            6 => Self::Error,
            7 => Self::Ping,
            8 => Self::Pong,
            9 => Self::SidecarHello,
            10 => Self::SidecarHelloAck,
            11 => Self::SidecarCommand,
            12 => Self::SidecarResult,
            13 => Self::SidecarStream,
            14 => Self::SidecarStreamEnd,
            15 => Self::SidecarCancel,
            16 => Self::DeliveryAck,
            _ => return Err(WireError::InvalidFrame("unknown frame type")),
        })
    }
}

/// A decoded binary frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame type.
    pub frame_type: FrameType,
    /// Type-specific flags. Sidecar v1 requires zero unless documented.
    pub flags: u16,
    /// Session identifier. Zero is reserved for connection control.
    pub session_id: u64,
    /// Connection-global monotonic receive sequence.
    pub sequence: u64,
    /// Bounded frame payload.
    pub payload: Vec<u8>,
}

/// Stateful frame reader. Any wire error poisons the connection.
pub struct FrameReader<R> {
    inner: R,
    recv_sequence: u64,
    poisoned: bool,
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Creates a reader whose first accepted sequence is one.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            recv_sequence: 0,
            poisoned: false,
        }
    }

    /// Reads and validates one complete frame.
    pub async fn read_frame(&mut self) -> Result<Frame, WireError> {
        if self.poisoned {
            return Err(WireError::Poisoned);
        }

        let result = self.read_frame_inner().await;
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    async fn read_frame_inner(&mut self) -> Result<Frame, WireError> {
        let mut header = [0u8; HEADER_SIZE];
        self.inner.read_exact(&mut header).await?;

        if u32::from_be_bytes(header[0..4].try_into().expect("fixed slice")) != MAGIC
            || header[4] != VERSION
        {
            return Err(WireError::InvalidFrame("invalid magic or version"));
        }

        let frame_type = FrameType::try_from(header[5])?;
        let flags = u16::from_be_bytes(header[6..8].try_into().expect("fixed slice"));
        let session_id = u64::from_be_bytes(header[8..16].try_into().expect("fixed slice"));
        let sequence = u64::from_be_bytes(header[16..24].try_into().expect("fixed slice"));
        let expected = self
            .recv_sequence
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;
        if sequence != expected {
            return Err(WireError::UnexpectedSequence {
                got: sequence,
                expected,
            });
        }

        let payload_size =
            u32::from_be_bytes(header[24..28].try_into().expect("fixed slice")) as usize;
        let maximum = frame_type.max_payload_size();
        if payload_size > maximum {
            return Err(WireError::PayloadTooLarge {
                size: payload_size,
                maximum,
            });
        }

        let mut payload = vec![0u8; payload_size];
        self.inner.read_exact(&mut payload).await?;
        self.recv_sequence = sequence;

        Ok(Frame {
            frame_type,
            flags,
            session_id,
            sequence,
            payload,
        })
    }
}

/// Stateful frame writer. A partial or failed write poisons the connection.
pub struct FrameWriter<W> {
    inner: W,
    send_sequence: u64,
    poisoned: bool,
}

impl<W> FrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Creates a writer whose first emitted sequence is one.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            send_sequence: 0,
            poisoned: false,
        }
    }

    /// Writes one frame and assigns its connection-global sequence.
    pub async fn write_frame(
        &mut self,
        frame_type: FrameType,
        flags: u16,
        session_id: u64,
        payload: &[u8],
    ) -> Result<(), WireError> {
        if self.poisoned {
            return Err(WireError::Poisoned);
        }
        let maximum = frame_type.max_payload_size();
        if payload.len() > maximum {
            return Err(WireError::PayloadTooLarge {
                size: payload.len(),
                maximum,
            });
        }
        let payload_size =
            u32::try_from(payload.len()).map_err(|_| WireError::PayloadTooLarge {
                size: payload.len(),
                maximum,
            })?;
        let sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(WireError::SequenceExhausted)?;

        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4] = VERSION;
        header[5] = frame_type as u8;
        header[6..8].copy_from_slice(&flags.to_be_bytes());
        header[8..16].copy_from_slice(&session_id.to_be_bytes());
        header[16..24].copy_from_slice(&sequence.to_be_bytes());
        header[24..28].copy_from_slice(&payload_size.to_be_bytes());

        if let Err(error) = self.inner.write_all(&header).await {
            self.poisoned = true;
            return Err(error.into());
        }
        if let Err(error) = self.inner.write_all(payload).await {
            self.poisoned = true;
            return Err(error.into());
        }
        if let Err(error) = self.inner.flush().await {
            self.poisoned = true;
            return Err(error.into());
        }
        self.send_sequence = sequence;
        Ok(())
    }
}

/// Binary wire failure. Callers must close a poisoned connection.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Underlying I/O failed.
    #[error("sidecar frame I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Header or frame type is invalid.
    #[error("invalid sidecar frame: {0}")]
    InvalidFrame(&'static str),
    /// Receive sequence was not exactly the next value.
    #[error("unexpected sidecar frame sequence: got {got}, expected {expected}")]
    UnexpectedSequence {
        /// Received sequence.
        got: u64,
        /// Required sequence.
        expected: u64,
    },
    /// Payload exceeded the frame-type-specific bound.
    #[error("sidecar frame payload is too large: {size} > {maximum}")]
    PayloadTooLarge {
        /// Received or requested size.
        size: usize,
        /// Maximum accepted size.
        maximum: usize,
    },
    /// A monotonic sequence reached `u64::MAX`.
    #[error("sidecar frame sequence exhausted")]
    SequenceExhausted,
    /// A prior wire error made stream alignment unknowable.
    #[error("sidecar frame connection is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct WireVector {
        frame_type: u8,
        flags: u16,
        session_id: u64,
        sequence: u64,
        payload_hex: String,
        wire_hex: String,
    }

    #[tokio::test]
    async fn matches_go_wire_vector() {
        let vector: WireVector =
            serde_json::from_str(include_str!("../../../../testdata/sidecar-frame-v1.json"))
                .unwrap();
        assert_eq!(vector.frame_type, FrameType::SidecarHello as u8);
        assert_eq!(vector.sequence, 1);
        let payload = from_hex(&vector.payload_hex);
        let (writer_io, mut raw_reader) = tokio::io::duplex(128);
        let mut writer = FrameWriter::new(writer_io);
        writer
            .write_frame(
                FrameType::SidecarHello,
                vector.flags,
                vector.session_id,
                &payload,
            )
            .await
            .unwrap();

        let mut wire = vec![0u8; HEADER_SIZE + payload.len()];
        raw_reader.read_exact(&mut wire).await.unwrap();
        assert_eq!(to_hex(&wire), vector.wire_hex);
    }

    #[tokio::test]
    async fn round_trips_and_rejects_sequence_gap() {
        let (writer_io, reader_io) = tokio::io::duplex(128);
        let mut writer = FrameWriter::new(writer_io);
        let mut reader = FrameReader::new(reader_io);
        writer
            .write_frame(FrameType::SidecarCommand, 0, 7, b"command")
            .await
            .unwrap();
        let frame = reader.read_frame().await.unwrap();
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.sequence, 1);
        assert_eq!(frame.payload, b"command");

        let (mut raw_writer, reader_io) = tokio::io::duplex(128);
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4] = VERSION;
        header[5] = FrameType::Ping as u8;
        header[16..24].copy_from_slice(&2u64.to_be_bytes());
        raw_writer.write_all(&header).await.unwrap();
        let mut reader = FrameReader::new(reader_io);
        assert!(matches!(
            reader.read_frame().await,
            Err(WireError::UnexpectedSequence {
                got: 2,
                expected: 1
            })
        ));
        assert!(matches!(
            reader.read_frame().await,
            Err(WireError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_stream_from_header() {
        let (mut raw_writer, reader_io) = tokio::io::duplex(128);
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        header[4] = VERSION;
        header[5] = FrameType::SidecarStream as u8;
        header[16..24].copy_from_slice(&1u64.to_be_bytes());
        header[24..28].copy_from_slice(&((MAX_DATA_FRAME_SIZE + 1) as u32).to_be_bytes());
        raw_writer.write_all(&header).await.unwrap();

        let mut reader = FrameReader::new(reader_io);
        assert!(matches!(
            reader.read_frame().await,
            Err(WireError::PayloadTooLarge { .. })
        ));
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write;

        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
    }

    fn from_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
