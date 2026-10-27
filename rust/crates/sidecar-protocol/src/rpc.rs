//! Role-bound local RPC messages for TokenHive sidecars.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    Capabilities, FrameReader, FrameType, FrameWriter, NegotiationError, PROTOCOL_VERSION, Role,
    WireError, validate_capabilities,
};

/// Maximum serialized hello or hello-ack size.
pub const MAX_HELLO_SIZE: usize = 16 << 10;
/// Maximum serialized command or result metadata size.
pub const MAX_COMMAND_SIZE: usize = 64 << 10;
/// Maximum aggregate bytes carried by one sidecar stream.
pub const MAX_STREAM_SIZE: usize = 16 << 20;
/// Maximum stable cancellation reason code size.
pub const MAX_CANCEL_REASON_SIZE: usize = 256;

/// Client hello sent by a Go service to its local Rust sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcHello {
    /// Required local RPC protocol version.
    pub protocol_version: u16,
    /// Sidecar role the client intended to connect to.
    pub expected_role: Role,
}

/// Successful sidecar hello response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcHelloAck {
    /// Capabilities of the connected sidecar.
    pub capabilities: Capabilities,
}

/// Sidecar operation name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Allocates a Hub MPC-TLS session.
    CreateSession,
    /// Runs the role-specific side of the MPC-TLS handshake.
    RunHandshake,
    /// Selectively encrypts a canonical request.
    EncryptRequest,
    /// Feeds upstream TLS records to the Hub engine.
    FeedServerRecords,
    /// Closes a Hub session.
    CloseSession,
    /// Binds a Provider-local credential reference.
    BindCredential,
    /// Contributes Provider inputs to selective request encryption.
    ContributeRequestEncryption,
    /// Destroys a Provider session and its secret state.
    DestroySession,
    /// Attaches a dedicated full-duplex MPC peer channel.
    AttachMpcChannel,
    /// Attaches a Provider-local, policy-checked upstream channel.
    AttachUpstreamChannel,
    /// Attaches a Hub-local authenticated plaintext response channel.
    AttachResponseChannel,
}

impl Operation {
    fn allowed_for(self, role: Role) -> bool {
        match role {
            Role::Hub => matches!(
                self,
                Self::CreateSession
                    | Self::RunHandshake
                    | Self::EncryptRequest
                    | Self::FeedServerRecords
                    | Self::CloseSession
                    | Self::AttachMpcChannel
                    | Self::AttachResponseChannel
            ),
            Role::Provider => matches!(
                self,
                Self::BindCredential
                    | Self::RunHandshake
                    | Self::ContributeRequestEncryption
                    | Self::DestroySession
                    | Self::AttachMpcChannel
                    | Self::AttachUpstreamChannel
            ),
        }
    }
}

/// Sidecar command metadata. Bulk bytes are carried in stream frames.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcCommand {
    /// Non-zero request identifier unique within the connection.
    pub request_id: u64,
    /// Requested role-specific operation.
    pub operation: Operation,
    /// Operation metadata. It must not contain Provider credentials.
    pub params: Value,
}

/// Result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcStatus {
    /// Operation completed successfully.
    Ok,
    /// Operation failed and the session should follow the returned error code.
    Error,
}

/// Sidecar command result metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcResult {
    /// Request identifier copied from the command.
    pub request_id: u64,
    /// Result status.
    pub status: RpcStatus,
    /// Structured non-secret output for a successful operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// Stable machine-readable failure code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Redacted human-readable failure detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl RpcResult {
    /// Creates a successful result with optional structured output.
    pub fn ok(request_id: u64, data: Option<Value>) -> Self {
        Self {
            request_id,
            status: RpcStatus::Ok,
            data,
            error_code: None,
            error_message: None,
        }
    }

    /// Creates a redacted error result.
    pub fn error(request_id: u64, code: impl Into<String>, message: &'static str) -> Self {
        Self {
            request_id,
            status: RpcStatus::Error,
            data: None,
            error_code: Some(code.into()),
            error_message: Some(message.to_owned()),
        }
    }
}

/// Complete input received for one streaming operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamInput {
    /// All stream chunks through the explicit end marker.
    Complete(Vec<u8>),
    /// The peer cancelled the operation with an optional stable reason code.
    Cancelled(Option<String>),
}

/// Accepts the initial role/version hello and writes sidecar capabilities.
pub async fn accept_hello<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut FrameWriter<W>,
    capabilities: Capabilities,
) -> Result<(), RpcError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let frame = reader.read_frame().await?;
    validate_control_frame(&frame, FrameType::SidecarHello, MAX_HELLO_SIZE)?;
    let hello: RpcHello = serde_json::from_slice(&frame.payload)?;
    if hello.protocol_version != PROTOCOL_VERSION {
        return Err(RpcError::ProtocolVersion(hello.protocol_version));
    }
    if hello.expected_role != capabilities.role {
        return Err(RpcError::Role {
            expected: hello.expected_role,
            actual: capabilities.role,
        });
    }
    validate_capabilities(&capabilities, capabilities.role)?;

    let payload = serde_json::to_vec(&RpcHelloAck { capabilities })?;
    if payload.len() > MAX_HELLO_SIZE {
        return Err(RpcError::MetadataTooLarge {
            size: payload.len(),
            maximum: MAX_HELLO_SIZE,
        });
    }
    writer
        .write_frame(FrameType::SidecarHelloAck, 0, 0, &payload)
        .await?;
    Ok(())
}

/// Reads and validates one role-specific sidecar command.
pub async fn read_command<R>(
    reader: &mut FrameReader<R>,
    role: Role,
) -> Result<(u64, RpcCommand), RpcError>
where
    R: AsyncRead + Unpin,
{
    let frame = reader.read_frame().await?;
    if frame.frame_type != FrameType::SidecarCommand || frame.flags != 0 || frame.session_id == 0 {
        return Err(RpcError::InvalidFrame(
            "expected command with zero flags and non-zero session",
        ));
    }
    if frame.payload.len() > MAX_COMMAND_SIZE {
        return Err(RpcError::MetadataTooLarge {
            size: frame.payload.len(),
            maximum: MAX_COMMAND_SIZE,
        });
    }

    let command: RpcCommand = serde_json::from_slice(&frame.payload)?;
    if command.request_id == 0 {
        return Err(RpcError::InvalidCommand("request_id must be non-zero"));
    }
    if !command.operation.allowed_for(role) {
        return Err(RpcError::OperationRole {
            operation: command.operation,
            role,
        });
    }
    Ok((frame.session_id, command))
}

/// Writes one bounded sidecar result.
pub async fn write_result<W>(
    writer: &mut FrameWriter<W>,
    session_id: u64,
    result: &RpcResult,
) -> Result<(), RpcError>
where
    W: AsyncWrite + Unpin,
{
    if session_id == 0 || result.request_id == 0 {
        return Err(RpcError::InvalidCommand(
            "result session_id and request_id must be non-zero",
        ));
    }
    match result.status {
        RpcStatus::Ok if result.error_code.is_some() || result.error_message.is_some() => {
            return Err(RpcError::InvalidCommand(
                "successful result contains error fields",
            ));
        }
        RpcStatus::Error if result.error_code.is_none() || result.data.is_some() => {
            return Err(RpcError::InvalidCommand(
                "error result is missing error_code or contains success data",
            ));
        }
        _ => {}
    }
    let payload = serde_json::to_vec(result)?;
    if payload.len() > MAX_COMMAND_SIZE {
        return Err(RpcError::MetadataTooLarge {
            size: payload.len(),
            maximum: MAX_COMMAND_SIZE,
        });
    }
    writer
        .write_frame(FrameType::SidecarResult, 0, session_id, &payload)
        .await?;
    Ok(())
}

/// Reads a bounded stream for the current operation.
pub async fn read_stream<R>(
    reader: &mut FrameReader<R>,
    session_id: u64,
) -> Result<StreamInput, RpcError>
where
    R: AsyncRead + Unpin,
{
    if session_id == 0 {
        return Err(RpcError::InvalidCommand(
            "stream session_id must be non-zero",
        ));
    }

    let mut output = Vec::new();
    loop {
        let frame = reader.read_frame().await?;
        if frame.flags != 0 || frame.session_id != session_id {
            return Err(RpcError::InvalidFrame(
                "stream frame has invalid flags or session",
            ));
        }
        match frame.frame_type {
            FrameType::SidecarStream => {
                if frame.payload.is_empty() {
                    return Err(RpcError::InvalidFrame("empty sidecar stream chunk"));
                }
                let size = output.len().checked_add(frame.payload.len()).ok_or(
                    RpcError::MetadataTooLarge {
                        size: usize::MAX,
                        maximum: MAX_STREAM_SIZE,
                    },
                )?;
                if size > MAX_STREAM_SIZE {
                    return Err(RpcError::MetadataTooLarge {
                        size,
                        maximum: MAX_STREAM_SIZE,
                    });
                }
                output.extend_from_slice(&frame.payload);
            }
            FrameType::SidecarStreamEnd => {
                if !frame.payload.is_empty() {
                    return Err(RpcError::InvalidFrame(
                        "sidecar stream end payload must be empty",
                    ));
                }
                return Ok(StreamInput::Complete(output));
            }
            FrameType::SidecarCancel => {
                if frame.payload.len() > MAX_CANCEL_REASON_SIZE {
                    return Err(RpcError::MetadataTooLarge {
                        size: frame.payload.len(),
                        maximum: MAX_CANCEL_REASON_SIZE,
                    });
                }
                let reason = if frame.payload.is_empty() {
                    None
                } else {
                    let value = std::str::from_utf8(&frame.payload)
                        .map_err(|_| RpcError::InvalidFrame("cancel reason is not UTF-8"))?;
                    if !is_stable_code(value) {
                        return Err(RpcError::InvalidFrame("invalid cancel reason code"));
                    }
                    Some(value.to_owned())
                };
                return Ok(StreamInput::Cancelled(reason));
            }
            _ => {
                return Err(RpcError::InvalidFrame(
                    "expected sidecar stream, end, or cancel frame",
                ));
            }
        }
    }
}

/// Writes bytes as bounded stream frames followed by an explicit end marker.
pub async fn write_stream<W>(
    writer: &mut FrameWriter<W>,
    session_id: u64,
    bytes: &[u8],
) -> Result<(), RpcError>
where
    W: AsyncWrite + Unpin,
{
    if session_id == 0 {
        return Err(RpcError::InvalidCommand(
            "stream session_id must be non-zero",
        ));
    }
    if bytes.len() > MAX_STREAM_SIZE {
        return Err(RpcError::MetadataTooLarge {
            size: bytes.len(),
            maximum: MAX_STREAM_SIZE,
        });
    }
    for chunk in bytes.chunks(crate::MAX_DATA_FRAME_SIZE) {
        writer
            .write_frame(FrameType::SidecarStream, 0, session_id, chunk)
            .await?;
    }
    writer
        .write_frame(FrameType::SidecarStreamEnd, 0, session_id, &[])
        .await?;
    Ok(())
}

fn is_stable_code(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_control_frame(
    frame: &crate::Frame,
    expected_type: FrameType,
    maximum: usize,
) -> Result<(), RpcError> {
    if frame.frame_type != expected_type || frame.flags != 0 || frame.session_id != 0 {
        return Err(RpcError::InvalidFrame(
            "invalid connection-control frame metadata",
        ));
    }
    if frame.payload.len() > maximum {
        return Err(RpcError::MetadataTooLarge {
            size: frame.payload.len(),
            maximum,
        });
    }
    Ok(())
}

/// Local sidecar RPC failure. Wire/protocol errors require closing the socket.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Binary framing failed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Strict JSON encoding or decoding failed.
    #[error("invalid sidecar RPC JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Sidecar capability configuration is invalid.
    #[error(transparent)]
    Capabilities(#[from] NegotiationError),
    /// A frame was not valid in the current RPC state.
    #[error("invalid sidecar RPC frame: {0}")]
    InvalidFrame(&'static str),
    /// Peer requested an unsupported protocol version.
    #[error("unsupported sidecar RPC protocol version {0}")]
    ProtocolVersion(u16),
    /// Client connected to a sidecar with the wrong role.
    #[error("sidecar role mismatch: expected {expected:?}, got {actual:?}")]
    Role {
        /// Role requested by the client.
        expected: Role,
        /// Actual sidecar role.
        actual: Role,
    },
    /// JSON metadata exceeded its semantic limit.
    #[error("sidecar RPC metadata is too large: {size} > {maximum}")]
    MetadataTooLarge {
        /// Actual serialized size.
        size: usize,
        /// Maximum accepted serialized size.
        maximum: usize,
    },
    /// Command identifiers or structure were invalid.
    #[error("invalid sidecar RPC command: {0}")]
    InvalidCommand(&'static str),
    /// Operation is not available on the connected role.
    #[error("operation {operation:?} is not allowed for role {role:?}")]
    OperationRole {
        /// Rejected operation.
        operation: Operation,
        /// Connected sidecar role.
        role: Role,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn accepts_matching_role_and_rejects_wrong_role() {
        let (client, server) = tokio::io::duplex(4096);
        let (client_read, client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);
        let mut client_reader = FrameReader::new(client_read);
        let mut client_writer = FrameWriter::new(client_write);
        let mut server_reader = FrameReader::new(server_read);
        let mut server_writer = FrameWriter::new(server_write);

        let client_task = async {
            let payload = serde_json::to_vec(&RpcHello {
                protocol_version: PROTOCOL_VERSION,
                expected_role: Role::Hub,
            })
            .unwrap();
            client_writer
                .write_frame(FrameType::SidecarHello, 0, 0, &payload)
                .await
                .unwrap();
            client_reader.read_frame().await.unwrap()
        };
        let server_task = accept_hello(
            &mut server_reader,
            &mut server_writer,
            Capabilities::selective_mpc(Role::Hub),
        );
        let (frame, result) = tokio::join!(client_task, server_task);
        result.unwrap();
        assert_eq!(frame.frame_type, FrameType::SidecarHelloAck);

        let (client, server) = tokio::io::duplex(4096);
        let (_, client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);
        let mut client_writer = FrameWriter::new(client_write);
        let mut server_reader = FrameReader::new(server_read);
        let mut server_writer = FrameWriter::new(server_write);
        let payload = serde_json::to_vec(&RpcHello {
            protocol_version: PROTOCOL_VERSION,
            expected_role: Role::Provider,
        })
        .unwrap();
        client_writer
            .write_frame(FrameType::SidecarHello, 0, 0, &payload)
            .await
            .unwrap();
        assert!(matches!(
            accept_hello(
                &mut server_reader,
                &mut server_writer,
                Capabilities::selective_mpc(Role::Hub)
            )
            .await,
            Err(RpcError::Role { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_operation_for_wrong_role() {
        let (mut raw_writer, reader_io) = tokio::io::duplex(4096);
        let command = RpcCommand {
            request_id: 9,
            operation: Operation::BindCredential,
            params: json!({"credential_id": "local-ref"}),
        };
        let payload = serde_json::to_vec(&command).unwrap();
        let mut writer = FrameWriter::new(&mut raw_writer);
        writer
            .write_frame(FrameType::SidecarCommand, 0, 3, &payload)
            .await
            .unwrap();

        let mut reader = FrameReader::new(reader_io);
        assert!(matches!(
            read_command(&mut reader, Role::Hub).await,
            Err(RpcError::OperationRole { .. })
        ));
    }

    #[test]
    fn rejects_unknown_hello_fields() {
        let payload = br#"{"protocol_version":1,"expected_role":"hub","extra":true}"#;
        assert!(serde_json::from_slice::<RpcHello>(payload).is_err());
    }

    #[tokio::test]
    async fn stream_round_trips_across_frame_boundaries() {
        let bytes = vec![0x5a; crate::MAX_DATA_FRAME_SIZE + 7];
        let (writer_io, reader_io) = tokio::io::duplex(crate::MAX_DATA_FRAME_SIZE * 2);
        let mut writer = FrameWriter::new(writer_io);
        let mut reader = FrameReader::new(reader_io);

        let (write_result, read_result) = tokio::join!(
            write_stream(&mut writer, 42, &bytes),
            read_stream(&mut reader, 42)
        );
        write_result.unwrap();
        assert_eq!(read_result.unwrap(), StreamInput::Complete(bytes));
    }

    #[tokio::test]
    async fn stream_rejects_wrong_session_and_unstable_cancel_reason() {
        let (writer_io, reader_io) = tokio::io::duplex(256);
        let mut writer = FrameWriter::new(writer_io);
        let mut reader = FrameReader::new(reader_io);
        writer
            .write_frame(FrameType::SidecarStream, 0, 8, b"bytes")
            .await
            .unwrap();
        assert!(matches!(
            read_stream(&mut reader, 7).await,
            Err(RpcError::InvalidFrame(_))
        ));

        let (writer_io, reader_io) = tokio::io::duplex(256);
        let mut writer = FrameWriter::new(writer_io);
        let mut reader = FrameReader::new(reader_io);
        writer
            .write_frame(FrameType::SidecarCancel, 0, 7, b"contains secret detail")
            .await
            .unwrap();
        assert!(matches!(
            read_stream(&mut reader, 7).await,
            Err(RpcError::InvalidFrame(_))
        ));
    }

    #[tokio::test]
    async fn stream_accepts_stable_cancel_reason() {
        let (writer_io, reader_io) = tokio::io::duplex(256);
        let mut writer = FrameWriter::new(writer_io);
        let mut reader = FrameReader::new(reader_io);
        writer
            .write_frame(FrameType::SidecarCancel, 0, 7, b"deadline_exceeded")
            .await
            .unwrap();
        assert_eq!(
            read_stream(&mut reader, 7).await.unwrap(),
            StreamInput::Cancelled(Some("deadline_exceeded".to_owned()))
        );
    }
}
