use futures::{StreamExt, channel::mpsc};

const SERVER_RECORD_BUFFER: usize = 16;

/// One encrypted TLS 1.2 server-to-client record observed by the Hub follower.
#[derive(Debug)]
pub struct ServerRecord {
    pub(crate) sequence: u64,
    content_type: u8,
    protocol_version: u16,
    explicit_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

impl ServerRecord {
    pub(crate) fn new(
        sequence: u64,
        content_type: u8,
        protocol_version: u16,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: Vec<u8>,
    ) -> Self {
        Self {
            sequence,
            content_type,
            protocol_version,
            explicit_nonce,
            ciphertext,
            tag,
        }
    }

    /// Returns the TLS record sequence number used in GCM additional data.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the TLS content type byte.
    pub fn content_type(&self) -> u8 {
        self.content_type
    }

    /// Returns the wire protocol version.
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Returns the eight-byte explicit GCM nonce.
    pub fn explicit_nonce(&self) -> &[u8] {
        &self.explicit_nonce
    }

    /// Returns ciphertext without the detached GCM tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the detached GCM authentication tag.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }
}

/// Hub-only receiver for encrypted server records after the authenticated handshake.
pub struct ServerRecordReceiver {
    receiver: mpsc::Receiver<ServerRecord>,
}

impl std::fmt::Debug for ServerRecordReceiver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServerRecordReceiver")
            .finish_non_exhaustive()
    }
}

impl ServerRecordReceiver {
    pub(crate) fn new(receiver: mpsc::Receiver<ServerRecord>) -> Self {
        Self { receiver }
    }

    /// Waits for the next encrypted server record.
    pub async fn recv(&mut self) -> Option<ServerRecord> {
        self.receiver.next().await
    }
}

pub(crate) type ServerRecordSender = mpsc::Sender<ServerRecord>;

pub(crate) fn channel() -> (ServerRecordSender, ServerRecordReceiver) {
    let (sender, receiver) = mpsc::channel(SERVER_RECORD_BUFFER);
    (sender, ServerRecordReceiver::new(receiver))
}
