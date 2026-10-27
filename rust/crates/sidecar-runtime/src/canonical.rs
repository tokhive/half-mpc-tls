use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokenhive_sidecar_protocol::LARGE_MAX_REQUEST_BYTES;

const MAX_CREDENTIAL_LENGTH: usize = 512;
pub(crate) const MAX_REQUEST_LENGTH: usize = LARGE_MAX_REQUEST_BYTES as usize;
const REQUEST_START: &[u8] = b"POST /v1/chat/completions HTTP/1.1\r\nHost: ";
const AUTHORIZATION_START: &[u8] = b"\r\nAuthorization: Bearer ";
const CONTENT_LENGTH_START: &[u8] = b"\r\nContent-Type: application/json\r\nContent-Length: ";
const BODY_START: &[u8] = b"\r\nConnection: keep-alive\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestAdapter {
    OpenaiChatCompletionsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectiveRequestParams {
    pub(crate) task_id: String,
    pub(crate) adapter: RequestAdapter,
    pub(crate) credential_length: usize,
    pub(crate) public_request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretSpan {
    pub(crate) kind: &'static str,
    pub(crate) offset: usize,
    pub(crate) length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SecretLayout {
    pub(crate) version: u16,
    pub(crate) spans: Vec<SecretSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedRequest {
    pub(crate) hash: [u8; 32],
    pub(crate) model: String,
    pub(crate) streaming: bool,
    pub(crate) layout: SecretLayout,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CanonicalError {
    #[error("invalid selective request metadata")]
    InvalidMetadata,
    #[error("canonical request does not match the selected adapter")]
    InvalidTemplate,
    #[error("public request hash does not match canonical bytes")]
    HashMismatch,
}

pub(crate) fn validate_metadata(params: &SelectiveRequestParams) -> Result<(), CanonicalError> {
    if !valid_task_id(&params.task_id)
        || params.credential_length == 0
        || params.credential_length > MAX_CREDENTIAL_LENGTH
        || decode_hash(&params.public_request_hash).is_none()
    {
        return Err(CanonicalError::InvalidMetadata);
    }
    Ok(())
}

pub(crate) fn validate_request(
    params: &SelectiveRequestParams,
    expected_host: &str,
    request: &[u8],
) -> Result<ValidatedRequest, CanonicalError> {
    validate_metadata(params)?;
    if request.len() > MAX_REQUEST_LENGTH {
        return Err(CanonicalError::InvalidTemplate);
    }

    match params.adapter {
        RequestAdapter::OpenaiChatCompletionsV1 => {
            validate_openai_chat_completions(params, expected_host, request)
        }
    }
}

fn validate_openai_chat_completions(
    params: &SelectiveRequestParams,
    expected_host: &str,
    request: &[u8],
) -> Result<ValidatedRequest, CanonicalError> {
    let mut prefix = Vec::with_capacity(REQUEST_START.len() + expected_host.len() + 32);
    prefix.extend_from_slice(REQUEST_START);
    prefix.extend_from_slice(expected_host.as_bytes());
    prefix.extend_from_slice(AUTHORIZATION_START);
    let credential_offset = prefix.len();

    let request_after_prefix = request
        .strip_prefix(prefix.as_slice())
        .ok_or(CanonicalError::InvalidTemplate)?;
    let (credential_slot, request_after_credential) = request_after_prefix
        .split_at_checked(params.credential_length)
        .ok_or(CanonicalError::InvalidTemplate)?;
    if credential_slot.iter().any(|byte| *byte != 0) {
        return Err(CanonicalError::InvalidTemplate);
    }
    let request_after_length_header = request_after_credential
        .strip_prefix(CONTENT_LENGTH_START)
        .ok_or(CanonicalError::InvalidTemplate)?;
    let length_end = request_after_length_header
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(CanonicalError::InvalidTemplate)?;
    let length_bytes = &request_after_length_header[..length_end];
    if length_bytes.is_empty()
        || (length_bytes.len() > 1 && length_bytes[0] == b'0')
        || !length_bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(CanonicalError::InvalidTemplate);
    }
    let declared_length = std::str::from_utf8(length_bytes)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(CanonicalError::InvalidTemplate)?;
    let body = request_after_length_header[length_end..]
        .strip_prefix(BODY_START)
        .ok_or(CanonicalError::InvalidTemplate)?;
    if body.len() != declared_length {
        return Err(CanonicalError::InvalidTemplate);
    }
    let (model, streaming) = validate_openai_body(body)?;

    let expected_hash = decode_hash(&params.public_request_hash)
        .expect("metadata validation guarantees a decoded hash");
    let actual_hash: [u8; 32] = Sha256::digest(request).into();
    if actual_hash != expected_hash {
        return Err(CanonicalError::HashMismatch);
    }

    Ok(ValidatedRequest {
        hash: actual_hash,
        model,
        streaming,
        layout: SecretLayout {
            version: 1,
            spans: vec![SecretSpan {
                kind: "bearer_credential",
                offset: credential_offset,
                length: params.credential_length,
            }],
        },
    })
}

fn validate_openai_body(body: &[u8]) -> Result<(String, bool), CanonicalError> {
    let body_value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| CanonicalError::InvalidTemplate)?;
    let body_object = body_value
        .as_object()
        .ok_or(CanonicalError::InvalidTemplate)?;
    let model = body_object
        .get("model")
        .and_then(serde_json::Value::as_str)
        .filter(|model| valid_model_id(model))
        .ok_or(CanonicalError::InvalidTemplate)?
        .to_owned();
    let streaming = match body_object.get("stream") {
        None => false,
        Some(value) => value.as_bool().ok_or(CanonicalError::InvalidTemplate)?,
    };
    let stream_options = body_object.get("stream_options");
    if !streaming {
        if stream_options.is_some() {
            return Err(CanonicalError::InvalidTemplate);
        }
        return Ok((model, false));
    }
    let include_usage = stream_options
        .and_then(serde_json::Value::as_object)
        .and_then(|options| options.get("include_usage"))
        .and_then(serde_json::Value::as_bool)
        .ok_or(CanonicalError::InvalidTemplate)?;
    if !include_usage {
        return Err(CanonicalError::InvalidTemplate);
    }
    Ok((model, true))
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':' | b'/')
        })
}

fn valid_task_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        adapter: RequestAdapter,
        host: String,
        credential_length: usize,
        canonical_request_hex: String,
        public_request_hash: String,
        secret_offset: usize,
        secret_length: usize,
    }

    #[test]
    fn validates_cross_language_request_vector() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../../testdata/canonical-request-v1.json"
        ))
        .unwrap();
        let request = decode_hex(&vector.canonical_request_hex);
        let params = SelectiveRequestParams {
            task_id: "task_01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned(),
            adapter: vector.adapter,
            credential_length: vector.credential_length,
            public_request_hash: vector.public_request_hash,
        };
        let validated = validate_request(&params, &vector.host, &request).unwrap();
        assert_eq!(validated.model, "gpt-4o");
        assert!(!validated.streaming);
        assert_eq!(validated.layout.spans.len(), 1);
        assert_eq!(validated.layout.spans[0].offset, vector.secret_offset);
        assert_eq!(validated.layout.spans[0].length, vector.secret_length);
    }

    #[test]
    fn binds_streaming_usage_policy_from_hashed_body() {
        let valid = br#"{"model":"gpt-5","stream":true,"stream_options":{"include_usage":true}}"#;
        assert_eq!(
            validate_openai_body(valid).unwrap(),
            ("gpt-5".to_owned(), true)
        );

        for invalid in [
            br#"{"model":"gpt-5","stream":true}"#.as_slice(),
            br#"{"model":"gpt-5","stream":true,"stream_options":{}}"#.as_slice(),
            br#"{"model":"gpt-5","stream":true,"stream_options":{"include_usage":false}}"#
                .as_slice(),
            br#"{"model":"gpt-5","stream":false,"stream_options":{"include_usage":true}}"#
                .as_slice(),
            br#"{"model":"gpt-5","stream":"true"}"#.as_slice(),
        ] {
            assert!(matches!(
                validate_openai_body(invalid),
                Err(CanonicalError::InvalidTemplate)
            ));
        }
    }

    #[test]
    fn rejects_request_above_mpc_capacity_before_parsing() {
        let request = vec![b'x'; MAX_REQUEST_LENGTH + 1];
        let params = SelectiveRequestParams {
            task_id: "task-capacity".to_owned(),
            adapter: RequestAdapter::OpenaiChatCompletionsV1,
            credential_length: 32,
            public_request_hash: "00".repeat(32),
        };
        assert!(matches!(
            validate_request(&params, "api.openai.com", &request),
            Err(CanonicalError::InvalidTemplate)
        ));
    }

    #[test]
    fn rejects_missing_or_invalid_model_even_with_matching_hash() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../../testdata/canonical-request-v1.json"
        ))
        .unwrap();
        let original = decode_hex(&vector.canonical_request_hex);
        let body_offset = original
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let invalid_body = br#"{"messages":[],"model":"bad model"}"#;
        let mut invalid = original[..body_offset].to_vec();
        let content_length = b"65";
        let length_offset = invalid
            .windows(content_length.len())
            .rposition(|window| window == content_length)
            .unwrap();
        invalid.splice(
            length_offset..length_offset + content_length.len(),
            invalid_body.len().to_string().bytes(),
        );
        invalid.extend_from_slice(invalid_body);
        let hash: [u8; 32] = Sha256::digest(&invalid).into();
        let params = SelectiveRequestParams {
            task_id: "task-model".to_owned(),
            adapter: vector.adapter,
            credential_length: vector.credential_length,
            public_request_hash: hash.iter().map(|byte| format!("{byte:02x}")).collect(),
        };
        assert!(matches!(
            validate_request(&params, &vector.host, &invalid),
            Err(CanonicalError::InvalidTemplate)
        ));
    }

    #[test]
    fn rejects_modified_public_or_secret_slot_bytes() {
        let vector: Vector = serde_json::from_str(include_str!(
            "../../../../testdata/canonical-request-v1.json"
        ))
        .unwrap();
        let params = SelectiveRequestParams {
            task_id: "task-7".to_owned(),
            adapter: vector.adapter,
            credential_length: vector.credential_length,
            public_request_hash: vector.public_request_hash,
        };
        let mut public_modified = decode_hex(&vector.canonical_request_hex);
        let public_character = public_modified.len() - 3;
        public_modified[public_character] = b'p';
        assert!(matches!(
            validate_request(&params, &vector.host, &public_modified),
            Err(CanonicalError::HashMismatch)
        ));

        let mut secret_modified = decode_hex(&vector.canonical_request_hex);
        secret_modified[vector.secret_offset] = b'x';
        assert!(matches!(
            validate_request(&params, &vector.host, &secret_modified),
            Err(CanonicalError::InvalidTemplate)
        ));
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
