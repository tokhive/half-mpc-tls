//! Adapter from the existing sidecar lifecycle to the one-shot TLS 1.3 engine.
use super::*;

pub(super) struct ProviderEngine {
    engine: tokenhive_tls13::Provider,
    delivery: Arc<DeliveryState>,
    used: bool,
}

struct Request {
    engine: Box<ProviderEngine>,
    bytes: Vec<u8>,
    credential: Zeroizing<Vec<u8>>,
    span: std::ops::Range<usize>,
    params: SelectiveRequestParams,
    validated: canonical::ValidatedRequest,
}

impl Runtime {
    pub(super) async fn handshake13(
        &self,
        inputs: HandshakeInputs,
    ) -> Result<HandshakeOutput, EngineError> {
        let policy = |p: UpstreamPolicy| tokenhive_tls13::Policy {
            server_name: p.server_name,
            max_request: self.limits.max_sent_data,
            max_response: self.limits.max_recv_data,
        };
        match inputs {
            HandshakeInputs::Hub {
                policy: p,
                mpc_channel,
                response_channel,
            } => tokenhive_tls13::hub_handshake(
                mpc_channel,
                response_channel,
                self.root_store.clone(),
                policy(p),
            )
            .await
            .map(|engine| HandshakeOutput::Hub13(Box::new(engine)))
            .map_err(|e| tlsn_stage_error("TLS 1.3 Hub handshake", e)),
            HandshakeInputs::Provider {
                policy: p,
                mpc_channel,
                upstream_channel,
            } => {
                let delivery = Arc::clone(&upstream_channel.delivery);
                let engine =
                    tokenhive_tls13::provider_handshake(mpc_channel, upstream_channel, policy(p))
                        .await
                        .map_err(|e| tlsn_stage_error("TLS 1.3 Provider handshake", e))?;
                Ok(HandshakeOutput::Provider13(Box::new(ProviderEngine {
                    engine,
                    delivery,
                    used: false,
                })))
            }
        }
    }

    pub(super) fn prepare_hub13(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        let mut registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return internal_error(request_id),
        };
        let Some(session) = registry.sessions.get_mut(&session_id) else {
            return RpcResult::error(request_id, "session_not_found", "session does not exist");
        };
        if session.owner != owner {
            return RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            );
        }
        if session.busy {
            return RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            );
        }
        let params = match serde_json::from_value::<SelectiveRequestParams>(params) {
            Ok(p) => p,
            Err(_) => return invalid_params(request_id, "invalid_params"),
        };
        let (Some(request), SessionBinding::Hub(policy)) = (stream, &session.binding) else {
            return invalid_params(request_id, "invalid_params");
        };
        let validated = match validate_request(&params, &policy.server_name, &request) {
            Ok(v) => v,
            Err(_) => return invalid_params(request_id, "invalid_canonical_request"),
        };
        if request.len() > self.limits.max_sent_data {
            return invalid_params(request_id, "request_capacity_exceeded");
        }
        if !matches!(session.engine, EngineState::Hub13Ready(_)) {
            return RpcResult::error(
                request_id,
                "invalid_state",
                "Hub TLS 1.3 engine is not ready",
            );
        }
        let span = &validated.layout.spans[0];
        let span = span.offset..span.offset + span.length;
        let EngineState::Hub13Ready(mut engine) =
            std::mem::replace(&mut session.engine, EngineState::Failed)
        else {
            unreachable!()
        };
        // Go prepares Hub first, then invokes Provider. Returning before the MPC
        // work completes avoids a cross-RPC deadlock. Drop/close aborts the actor.
        session.engine = EngineState::Hub13Running(AbortTask(tokio::spawn(async move {
            if matches!(
                tokio::time::timeout(REQUEST_DELIVERY_TIMEOUT, engine.request(&request, span))
                    .await,
                Ok(Ok(()))
            ) {
                let _ = engine.response().await;
            }
        })));
        RpcResult::ok(
            request_id,
            Some(json!({"state":"request_prepared","task_id":params.task_id,
            "requested_model":validated.model,"streaming":validated.streaming,"public_request_hash":encode_hash(&validated.hash)})),
        )
    }

    fn take_provider13(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> Result<Request, RpcResult> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| internal_error(request_id))?;
        let session = registry.sessions.get_mut(&session_id).ok_or_else(|| {
            RpcResult::error(request_id, "session_not_found", "session does not exist")
        })?;
        if session.owner != owner {
            return Err(RpcResult::error(
                request_id,
                "session_owner_mismatch",
                "session belongs to another local connection",
            ));
        }
        if session.busy {
            return Err(RpcResult::error(
                request_id,
                "session_busy",
                "session has an active operation",
            ));
        }
        let params = serde_json::from_value::<SelectiveRequestParams>(params)
            .map_err(|_| invalid_params(request_id, "invalid_params"))?;
        let (bytes, credential_id, policy) = match (stream, &session.binding) {
            (
                Some(bytes),
                SessionBinding::Provider {
                    credential_id,
                    upstream_policy,
                },
            ) => (bytes, credential_id, upstream_policy),
            _ => return Err(invalid_params(request_id, "invalid_params")),
        };
        let validated = validate_request(&params, &policy.server_name, &bytes)
            .map_err(|_| invalid_params(request_id, "invalid_canonical_request"))?;
        if bytes.len() > self.limits.max_sent_data {
            return Err(invalid_params(request_id, "request_capacity_exceeded"));
        }
        let credential = self
            .credential_resolver
            .resolve(credential_id)
            .ok_or_else(|| {
                RpcResult::error(
                    request_id,
                    "credential_not_found",
                    "bound credential could not be resolved",
                )
            })?;
        if credential.len() != params.credential_length {
            return Err(RpcResult::error(
                request_id,
                "credential_length_mismatch",
                "credential length does not match request metadata",
            ));
        }
        if !matches!(&session.engine,EngineState::Provider13Running(engine) if !engine.used) {
            return Err(RpcResult::error(
                request_id,
                "invalid_state",
                "Provider TLS 1.3 session is unavailable or used",
            ));
        }
        let span = &validated.layout.spans[0];
        let span = span.offset..span.offset + span.length;
        let EngineState::Provider13Running(mut engine) =
            std::mem::replace(&mut session.engine, EngineState::Failed)
        else {
            unreachable!()
        };
        engine.used = true;
        session.busy = true;
        Ok(Request {
            engine,
            bytes,
            credential,
            span,
            params,
            validated,
        })
    }

    pub(super) async fn contribute_provider13(
        &self,
        owner: u64,
        session_id: u64,
        request_id: u64,
        params: Value,
        stream: Option<Vec<u8>>,
    ) -> RpcResult {
        let Request {
            mut engine,
            bytes,
            credential,
            span,
            params,
            validated,
        } = match self.take_provider13(owner, session_id, request_id, params, stream) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let operation = async {
            let before = futures::future::poll_fn(|cx| engine.delivery.poll_snapshot(0, cx))
                .await
                .map_err(|_| "delivery_state_failed")?;
            // One prefix record, one KeyUpdate and fragmented new-epoch body.
            let cut = span.end + 2;
            let records = (bytes.len() - cut).div_ceil(TLS_PLAINTEXT_FRAGMENT_SIZE) + 2;
            let wire_bytes = bytes.len() as u64 + 5 + 22 * records as u64;
            engine
                .engine
                .request(&bytes, span, &credential)
                .await
                .map_err(|_| "engine_io_failed")?;
            let after = futures::future::poll_fn(|cx| {
                engine.delivery.poll_snapshot(before.bytes + wire_bytes, cx)
            })
            .await
            .map_err(|_| "delivery_state_failed")?;
            let sent = after
                .bytes
                .checked_sub(before.bytes)
                .filter(|n| *n >= wire_bytes)
                .ok_or("delivery_state_failed")?;
            Ok::<_, &'static str>((after, sent))
        };
        let operation = tokio::time::timeout(REQUEST_DELIVERY_TIMEOUT, operation)
            .await
            .map_err(|_| "delivery_timeout")
            .and_then(|r| r);
        let mut registry = match self.registry.lock() {
            Ok(r) => r,
            Err(_) => return internal_error(request_id),
        };
        let Some(session) = registry.sessions.get_mut(&session_id) else {
            return RpcResult::error(
                request_id,
                "session_not_found",
                "session was destroyed during delivery",
            );
        };
        if session.owner != owner {
            return internal_error(request_id);
        }
        session.busy = false;
        match operation {
            Ok((delivery, request_bytes)) => {
                session.engine = EngineState::Provider13Running(engine);
                RpcResult::ok(
                    request_id,
                    Some(json!({"state":"request_delivered","task_id":params.task_id,
                    "requested_model":validated.model,"streaming":validated.streaming,"public_request_hash":encode_hash(&validated.hash),
                    "upstream_delivery":{"cumulative_bytes":delivery.bytes,"request_bytes":request_bytes,"sha256":encode_hash(&delivery.sha256)}})),
                )
            }
            Err(code) => {
                session.engine = EngineState::Failed;
                RpcResult::error(
                    request_id,
                    code,
                    "TLS 1.3 selective request encryption failed",
                )
            }
        }
    }
}
