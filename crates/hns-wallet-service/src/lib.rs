#![doc = "Private wallet service composition without browser-engine policy."]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hns_wallet_ffi::{
    APPROVAL_SCHEMA_VERSION, AccountSummary, ApprovalPrompt, ApprovalSummary, HostAuthorityFacts,
    HostFrame, MAX_PROVIDER_RESULT_BYTES, MAX_PUBLIC_STRING_BYTES, ModuleApprovalAction,
    PROVIDER_SCHEMA_VERSION, ProviderBinding, ProviderCapabilitySnapshot,
    ProviderEventEnvelope, ProviderEventPayload, ProviderNamespace, ServiceCapability,
    ServiceErrorCode, ServiceFailure, ServiceFrame, ServiceHello, ServiceLimits, ServiceRequest,
    ServiceResponse, SessionEnvelope, WALLET_ABI_VERSION, WalletRequest, WalletResponse,
    encode_service_frame,
};
use hns_wallet_provider::{
    ApprovedCall, HostAuthorityRegistration, Origin, PROVIDER_API_VERSION, PendingApproval,
    PermissionSnapshot, ProviderAction, ProviderCore, ProviderError, ProviderMethod,
    ProviderStateStore, SelectedNamespace,
};
use hns_wallet_store::WalletStore;
use hns_wallet_types::{
    ApprovalId, ApprovalKind, HostAuthorityHandleId, HostSessionId, ModuleId, PermissionCapability,
    ProviderApprovalId, ProviderRequestId, WalletServiceSessionId, WalletSessionId,
};
use serde_json::{Value, json};
use thiserror::Error;

pub const MAX_SEEN_REQUEST_IDS: usize = 4_096;
pub const MAX_SERVICE_PENDING_APPROVALS: usize = 128;

/// Execution boundary supplied by a wallet composition. The checked-in
/// subprocess uses [`UnavailableRuntime`], so no provider, value movement, or
/// browser capability is advertised merely because protocol source exists.
pub trait ServiceRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability>;

    fn supports_provider_method(&self, method: ProviderMethod) -> bool;

    fn prepare_approval(
        &mut self,
        approval: &PendingApproval,
    ) -> Result<ApprovalSummary, ServiceFailure>;

    /// Select the one minimized Handshake account that an approved origin may
    /// learn through `hns_requestAccounts`. The service validates and persists
    /// the exact account identifier before returning it.
    fn prepare_hns_account_grant(
        &mut self,
        _: &ApprovedCall,
    ) -> Result<AccountSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            ServiceCapability::ProviderDispatch,
        ))
    }

    fn execute_provider(&mut self, call: ApprovedCall) -> Result<Value, ServiceFailure>;

    fn lock_wallet(&mut self) -> Result<(), ServiceFailure>;

    fn execute_wallet(&mut self, request: WalletRequest) -> Result<WalletResponse, ServiceFailure>;
}

#[derive(Default)]
pub struct UnavailableRuntime;

impl ServiceRuntime for UnavailableRuntime {
    fn capabilities(&self) -> BTreeSet<ServiceCapability> {
        BTreeSet::new()
    }

    fn supports_provider_method(&self, _: ProviderMethod) -> bool {
        false
    }

    fn prepare_approval(&mut self, _: &PendingApproval) -> Result<ApprovalSummary, ServiceFailure> {
        Err(ServiceFailure::unsupported(ServiceCapability::ProviderDispatch))
    }

    fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
        Err(ServiceFailure::unsupported(ServiceCapability::ProviderDispatch))
    }

    fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
        Err(ServiceFailure::unsupported(ServiceCapability::WalletOperations))
    }

    fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
        Err(ServiceFailure::unsupported(ServiceCapability::WalletOperations))
    }
}

#[derive(Clone, Copy)]
struct SessionState {
    host_session_id: HostSessionId,
    restart_generation: u64,
    next_host_sequence: u64,
    next_service_sequence: u64,
}

#[derive(Clone, Copy)]
struct PendingState {
    binding: ProviderBinding,
    kind: ApprovalKind,
    expires_at_unix: u64,
}

/// One process-local service generation. Construction rotates both the service
/// and wallet session identifiers and starts with no authority handles,
/// approvals, replay entries, rate windows, request IDs, or event cursors.
/// The supplied state store remains the sole source of permission records and
/// tombstone generations.
pub struct WalletService<S, R> {
    provider: ProviderCore<S>,
    runtime: R,
    service_session_id: WalletServiceSessionId,
    wallet_session_id: WalletSessionId,
    capabilities: BTreeSet<ServiceCapability>,
    session: Option<SessionState>,
    seen_request_ids: BTreeSet<ProviderRequestId>,
    request_order: VecDeque<ProviderRequestId>,
    pending: BTreeMap<ProviderApprovalId, PendingState>,
    event_sequences: BTreeMap<(HostAuthorityHandleId, u64), u64>,
}

impl<S: ProviderStateStore, R: ServiceRuntime> WalletService<S, R> {
    pub fn new_ephemeral(state: S, runtime: R) -> Result<Self, ServiceError> {
        Self::new(state, runtime, false)
    }

    fn new(state: S, runtime: R, persistent_permissions: bool) -> Result<Self, ServiceError> {
        let service_session_id = random_service_session()?;
        let wallet_session_id = random_wallet_session()?;
        let mut capabilities = BTreeSet::from([
            ServiceCapability::CanonicalFraming,
            ServiceCapability::RestartIsolation,
            ServiceCapability::OpaqueAuthorityRegistry,
            ServiceCapability::StructuredApprovals,
            ServiceCapability::TypedEvents,
        ]);
        if persistent_permissions {
            capabilities.insert(ServiceCapability::PersistentPermissions);
        }
        capabilities.extend(runtime.capabilities());
        capabilities.remove(&ServiceCapability::BrowserIntegration);
        if !persistent_permissions {
            capabilities.remove(&ServiceCapability::PersistentPermissions);
        }
        if !capabilities.contains(&ServiceCapability::ProviderDispatch) {
            capabilities.remove(&ServiceCapability::ValueMovement);
        }
        Ok(Self {
            provider: ProviderCore::new(state, wallet_session_id, true),
            runtime,
            service_session_id,
            wallet_session_id,
            capabilities,
            session: None,
            seen_request_ids: BTreeSet::new(),
            request_order: VecDeque::new(),
            pending: BTreeMap::new(),
            event_sequences: BTreeMap::new(),
        })
    }

    pub fn process_frame(
        &mut self,
        encoded: &[u8],
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        let frame = hns_wallet_ffi::decode_host_frame(encoded)?;
        match frame {
            HostFrame::Hello { hello } => self.negotiate(hello),
            HostFrame::Request { envelope } => self.process_request(envelope, now_unix_ms),
        }
    }

    pub fn rotate_wallet_session(&mut self, locked: bool) -> Result<(), ServiceError> {
        self.pending.clear();
        self.event_sequences.clear();
        match random_wallet_session() {
            Ok(wallet_session_id) => {
                self.wallet_session_id = wallet_session_id;
                self.provider.set_wallet_state(wallet_session_id, locked);
                Ok(())
            }
            Err(error) => {
                self.provider.set_wallet_state(self.wallet_session_id, true);
                Err(error)
            }
        }
    }

    pub fn emit_event(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        payload: ProviderEventPayload,
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        let permission = match self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
        {
            Ok(permission) => permission,
            Err(error) => {
                self.event_sequences.clear();
                return Err(ServiceError::from(error));
            }
        };
        if permission.record.is_none()
            && !matches!(&payload, ProviderEventPayload::Disconnect { .. })
        {
            self.event_sequences.clear();
            return Err(ServiceError::Provider(ProviderError::Unauthorized));
        }
        let retire_after_emit = permission.record.is_none();
        let event_sequence = self
            .event_sequences
            .entry((authority_handle, authority_revision))
            .or_insert(0);
        *event_sequence = event_sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        let event_sequence = *event_sequence;
        let (session, channel_sequence) = self.next_service_sequence()?;
        let encoded = encode_service_frame(&ServiceFrame::Event {
            event: ProviderEventEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: session.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: session.restart_generation,
                channel_sequence,
                binding: ProviderBinding {
                    authority_handle,
                    authority_revision,
                    wallet_session_id: self.provider.wallet_session_id(),
                    permission_generation: permission.generation,
                },
                event_sequence,
                payload,
            },
        })
        .map_err(ServiceError::from);
        if retire_after_emit {
            self.event_sequences
                .remove(&(authority_handle, authority_revision));
        }
        encoded
    }

    fn negotiate(&mut self, hello: hns_wallet_ffi::HostHello) -> Result<Vec<u8>, ServiceError> {
        if self.session.is_some() {
            return Err(ServiceError::AlreadyNegotiated);
        }
        self.session = Some(SessionState {
            host_session_id: hello.host_session_id,
            restart_generation: hello.restart_generation,
            next_host_sequence: 1,
            next_service_sequence: 1,
        });
        encode_service_frame(&ServiceFrame::Hello {
            hello: ServiceHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: hello.platform,
                host_session_id: hello.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: hello.restart_generation,
                capabilities: self.capabilities.clone(),
                limits: ServiceLimits::default(),
            },
        })
        .map_err(ServiceError::from)
    }

    fn process_request(
        &mut self,
        envelope: SessionEnvelope<ServiceRequest>,
        now_unix_ms: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        self.accept_request_header(&envelope)?;
        self.prune_pending(now_unix_ms / 1_000);
        let request_id = envelope.request_id;
        let response = self
            .dispatch(envelope.body, now_unix_ms)
            .unwrap_or_else(|failure| ServiceResponse::Failure { failure });
        let (session, channel_sequence) = self.next_service_sequence()?;
        encode_service_frame(&ServiceFrame::Response {
            envelope: SessionEnvelope {
                protocol_version: WALLET_ABI_VERSION,
                host_session_id: session.host_session_id,
                service_session_id: self.service_session_id,
                restart_generation: session.restart_generation,
                channel_sequence,
                request_id,
                body: response,
            },
        })
        .map_err(ServiceError::from)
    }

    fn accept_request_header<T>(&mut self, envelope: &SessionEnvelope<T>) -> Result<(), ServiceError> {
        let session = self.session.as_mut().ok_or(ServiceError::HandshakeRequired)?;
        if envelope.host_session_id != session.host_session_id
            || envelope.service_session_id != self.service_session_id
            || envelope.restart_generation != session.restart_generation
        {
            return Err(ServiceError::SessionMismatch);
        }
        if envelope.channel_sequence != session.next_host_sequence {
            return Err(ServiceError::SequenceMismatch {
                expected: session.next_host_sequence,
                received: envelope.channel_sequence,
            });
        }
        if self.seen_request_ids.contains(&envelope.request_id) {
            return Err(ServiceError::DuplicateRequest);
        }
        session.next_host_sequence = session
            .next_host_sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        self.seen_request_ids.insert(envelope.request_id);
        self.request_order.push_back(envelope.request_id);
        if self.request_order.len() > MAX_SEEN_REQUEST_IDS {
            if let Some(expired) = self.request_order.pop_front() {
                self.seen_request_ids.remove(&expired);
            }
        }
        Ok(())
    }

    fn next_service_sequence(&mut self) -> Result<(SessionState, u64), ServiceError> {
        let session = self.session.as_mut().ok_or(ServiceError::HandshakeRequired)?;
        let sequence = session.next_service_sequence;
        session.next_service_sequence = sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        Ok((*session, sequence))
    }

    fn dispatch(
        &mut self,
        request: ServiceRequest,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        match request {
            ServiceRequest::RegisterAuthority {
                authority_handle,
                authority,
            } => {
                let revision = self.provider.register_authority(
                    authority_handle,
                    provider_authority(authority)?,
                    now_unix_ms,
                )
                .map_err(provider_failure)?;
                Ok(ServiceResponse::AuthorityRegistered {
                    authority_handle,
                    authority_revision: revision,
                })
            }
            ServiceRequest::ReplaceAuthority {
                authority_handle,
                expected_authority_revision,
                authority,
            } => {
                let revision = self.provider.replace_authority(
                    authority_handle,
                    expected_authority_revision,
                    provider_authority(authority)?,
                    now_unix_ms,
                )
                .map_err(provider_failure)?;
                self.pending
                    .retain(|_, pending| pending.binding.authority_handle != authority_handle);
                self.event_sequences
                    .retain(|(handle, _), _| *handle != authority_handle);
                Ok(ServiceResponse::AuthorityReplaced {
                    authority_handle,
                    authority_revision: revision,
                })
            }
            ServiceRequest::RevokeAuthority {
                authority_handle,
                expected_authority_revision,
            } => {
                self.provider
                    .revoke_authority(authority_handle, expected_authority_revision)
                    .map_err(provider_failure)?;
                self.pending
                    .retain(|_, pending| pending.binding.authority_handle != authority_handle);
                self.event_sequences
                    .retain(|(handle, _), _| *handle != authority_handle);
                Ok(ServiceResponse::AuthorityRevoked { authority_handle })
            }
            ServiceRequest::ProviderCapabilities {
                authority_handle,
                authority_revision,
            } => self.provider_capabilities(
                authority_handle,
                authority_revision,
                now_unix_ms,
            ),
            ServiceRequest::ProviderRequest {
                authority_handle,
                authority_revision,
                request_nonce,
                method,
                params,
            } => self.provider_request(
                authority_handle,
                authority_revision,
                request_nonce,
                method,
                params,
                now_unix_ms,
            ),
            ServiceRequest::ApprovalDecision {
                authority_handle,
                authority_revision,
                approval_id,
                decision,
            } => self.approval_decision(
                authority_handle,
                authority_revision,
                approval_id,
                decision,
                now_unix_ms,
            ),
            ServiceRequest::Wallet { request } => {
                if !self.capabilities.contains(&ServiceCapability::WalletOperations) {
                    return Err(ServiceFailure::unsupported(ServiceCapability::WalletOperations));
                }
                let response = self.runtime.execute_wallet(request)?;
                match &response {
                    WalletResponse::Locked => self
                        .rotate_wallet_session(true)
                        .map_err(ServiceFailure::from)?,
                    WalletResponse::Unlocked
                    | WalletResponse::WalletCreated { .. }
                    | WalletResponse::WalletRestored { .. } => self
                        .rotate_wallet_session(false)
                        .map_err(ServiceFailure::from)?,
                    _ => {}
                }
                Ok(ServiceResponse::Wallet { response })
            }
        }
    }

    fn provider_capabilities(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        let binding = self.provider_binding(
            authority_handle,
            authority_revision,
            now_unix_ms,
        )?;
        let capabilities = ProviderCapabilitySnapshot {
            provider_schema_version: PROVIDER_SCHEMA_VERSION,
            approval_schema_version: APPROVAL_SCHEMA_VERSION,
            wallet_session_id: binding.wallet_session_id,
            permission_generation: binding.permission_generation,
            methods: self.supported_provider_method_names(),
        };
        Ok(ServiceResponse::ProviderCapabilities {
            binding,
            capabilities,
        })
    }

    fn provider_request(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        request_nonce: u64,
        method_name: String,
        params: Value,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        if !self
            .capabilities
            .contains(&ServiceCapability::ProviderDispatch)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        let method = ProviderMethod::parse(&method_name).map_err(provider_failure)?;
        if matches!(
            method,
            ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
        ) {
            validate_empty_params(&params)?;
        }
        if method == ProviderMethod::WalletLock
            && !self
                .capabilities
                .contains(&ServiceCapability::WalletOperations)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ));
        }
        if method.approval().is_some_and(value_movement_approval)
            && !self
                .capabilities
                .contains(&ServiceCapability::ValueMovement)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ValueMovement,
            ));
        }
        if matches!(
            method,
            ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
        ) && !self
            .runtime
            .supports_provider_method(ProviderMethod::HnsRequestAccounts)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        if !service_owned_method(method) && !self.runtime.supports_provider_method(method) {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        let encoded_request = serde_json::to_vec(&json!({
            "method": method_name.clone(),
            "params": params,
        }))
        .map_err(|_| invalid_request("provider request encoding failed"))?;
        let action = match self.provider.request(
            authority_handle,
            authority_revision,
            request_nonce,
            now_unix_ms,
            &encoded_request,
        ) {
            Ok(action) => action,
            Err(error) => {
                if matches!(
                    &error,
                    ProviderError::Unauthorized | ProviderError::ClockRollback
                ) {
                    self.event_sequences.clear();
                }
                if matches!(&error, ProviderError::ClockRollback) {
                    self.pending.clear();
                }
                return Err(provider_failure(error));
            }
        };
        match action {
            ProviderAction::Execute(call) => {
                let value = self.execute_call(
                    authority_handle,
                    authority_revision,
                    call,
                    None,
                    now_unix_ms,
                )?;
                let binding =
                    self.provider_binding(authority_handle, authority_revision, now_unix_ms)?;
                Ok(ServiceResponse::ProviderResult { binding, value })
            }
            ProviderAction::ApprovalRequired(approval) => {
                if self.pending.len() >= MAX_SERVICE_PENDING_APPROVALS {
                    self.provider
                        .reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        )
                        .map_err(provider_failure)?;
                    return Err(invalid_request("too many pending approvals"));
                }
                let summary = match self.approval_summary(&approval) {
                    Ok(summary) => summary,
                    Err(failure) => {
                        let _ = self.provider.reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        );
                        return Err(failure);
                    }
                };
                let wire_id = match wire_approval_id(approval.id) {
                    Ok(wire_id) => wire_id,
                    Err(failure) => {
                        let _ = self.provider.reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        );
                        return Err(failure);
                    }
                };
                let expires_at_unix_ms = match approval
                    .expires_at_unix
                    .checked_mul(1_000)
                {
                    Some(expiry) => expiry,
                    None => {
                        let _ = self.provider.reject(
                            authority_handle,
                            authority_revision,
                            approval.id,
                            now_unix_ms,
                        );
                        return Err(invalid_request("approval expiry overflow"));
                    }
                };
                let prompt = ApprovalPrompt {
                    approval_id: wire_id,
                    binding: ProviderBinding {
                        authority_handle,
                        authority_revision,
                        wallet_session_id: approval.wallet_session,
                        permission_generation: approval.permission_generation,
                    },
                    origin: approval.call.origin.as_str().to_owned(),
                    method: method_name,
                    expires_at_unix_ms,
                    summary,
                };
                if let Err(error) = prompt.validate(approval.kind, now_unix_ms) {
                    let _ = self.provider.reject(
                        authority_handle,
                        authority_revision,
                        approval.id,
                        now_unix_ms,
                    );
                    return Err(ServiceFailure {
                        code: ServiceErrorCode::InvalidRequest,
                        message: error.to_string(),
                        unsupported_capability: None,
                    });
                }
                self.pending.insert(
                    wire_id,
                    PendingState {
                        binding: prompt.binding,
                        kind: approval.kind,
                        expires_at_unix: approval.expires_at_unix,
                    },
                );
                Ok(ServiceResponse::ApprovalRequired { approval: prompt })
            }
        }
    }

    fn approval_decision(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        approval_id: ProviderApprovalId,
        decision: hns_wallet_ffi::ApprovalDecision,
        now_unix_ms: u64,
    ) -> Result<ServiceResponse, ServiceFailure> {
        let pending = self
            .pending
            .get(&approval_id)
            .copied()
            .ok_or_else(stale_approval)?;
        if pending.binding.authority_handle != authority_handle
            || pending.binding.authority_revision != authority_revision
            || pending.expires_at_unix <= now_unix_ms / 1_000
        {
            return Err(stale_approval());
        }
        let binding = self.provider_binding(
            authority_handle,
            authority_revision,
            now_unix_ms,
        )?;
        if pending.binding != binding {
            return Err(stale_approval());
        }
        let internal_id = ApprovalId::new(approval_id.into_bytes());
        match decision {
            hns_wallet_ffi::ApprovalDecision::Reject => {
                self.provider.reject(
                    authority_handle,
                    authority_revision,
                    internal_id,
                    now_unix_ms,
                )
                .map_err(provider_failure)?;
                self.pending.remove(&approval_id);
                Ok(ServiceResponse::ApprovalRejected { approval_id })
            }
            hns_wallet_ffi::ApprovalDecision::Approve => {
                let call = self.provider.approve(
                    authority_handle,
                    authority_revision,
                    internal_id,
                    now_unix_ms,
                )
                .map_err(provider_failure)?;
                if call.method.approval() != Some(pending.kind) {
                    self.pending.remove(&approval_id);
                    return Err(stale_approval());
                }
                self.pending.remove(&approval_id);
                let value = self.execute_call(
                    authority_handle,
                    authority_revision,
                    call,
                    Some(pending.binding.permission_generation),
                    now_unix_ms,
                )?;
                let binding =
                    self.provider_binding(authority_handle, authority_revision, now_unix_ms)?;
                Ok(ServiceResponse::ProviderResult { binding, value })
            }
        }
    }

    fn approval_summary(
        &mut self,
        approval: &PendingApproval,
    ) -> Result<ApprovalSummary, ServiceFailure> {
        let summary = match approval.call.method {
            ProviderMethod::WalletRequestPermissions | ProviderMethod::HnsRequestAccounts => {
                Ok(ApprovalSummary::Permissions {
                    capabilities: requested_capabilities(&approval.call)?,
                })
            }
            ProviderMethod::WalletEnableModule | ProviderMethod::WalletDisableModule => {
                let module = requested_module(&approval.call.params)?;
                let action = if approval.call.method == ProviderMethod::WalletEnableModule {
                    ModuleApprovalAction::Enable
                } else {
                    ModuleApprovalAction::Disable
                };
                Ok(ApprovalSummary::ModuleEnablement { module, action })
            }
            _ => self.runtime.prepare_approval(approval),
        }?;
        validate_approval_summary(&approval.call, &summary)?;
        Ok(summary)
    }

    fn execute_call(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: ApprovedCall,
        expected_permission_generation: Option<u64>,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        match call.method {
            ProviderMethod::WalletGetCapabilities => Ok(json!({
                "providerApiVersion": PROVIDER_API_VERSION,
                "methods": self.supported_provider_method_names(),
            })),
            ProviderMethod::WalletGetPermissions => {
                let permission = self
                    .provider
                    .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
                    .map_err(provider_failure)?;
                if permission.record.is_none() {
                    self.event_sequences.clear();
                }
                permission_value(permission)
            }
            ProviderMethod::WalletRevokePermissions => {
                let generation = self
                    .provider
                    .revoke_permissions(authority_handle, authority_revision, now_unix_ms)
                    .map_err(provider_failure)?;
                self.pending.clear();
                self.event_sequences.clear();
                Ok(json!({
                    "permissionGeneration": generation,
                    "capabilities": [],
                    "accounts": []
                }))
            }
            ProviderMethod::WalletRequestPermissions => {
                let capabilities = requested_capabilities(&call)?;
                let expected_generation =
                    expected_permission_generation.ok_or_else(stale_approval)?;
                let permission = self
                    .provider
                    .grant_scoped_permissions_at_generation(
                        authority_handle,
                        authority_revision,
                        expected_generation,
                        capabilities,
                        BTreeSet::new(),
                        BTreeSet::new(),
                        now_unix_ms,
                        None,
                    )
                    .map_err(provider_failure)?;
                self.pending.clear();
                self.event_sequences.clear();
                permission_value(PermissionSnapshot {
                    generation: permission.generation,
                    record: Some(permission),
                })
            }
            ProviderMethod::HnsRequestAccounts => self.approve_hns_account_grant(
                authority_handle,
                authority_revision,
                &call,
                expected_permission_generation.ok_or_else(stale_approval)?,
                now_unix_ms,
            ),
            ProviderMethod::HnsAccounts => {
                self.approved_hns_accounts(authority_handle, authority_revision, &call, now_unix_ms)
            }
            ProviderMethod::WalletLock => {
                self.runtime.lock_wallet()?;
                self.rotate_wallet_session(true)
                    .map_err(ServiceFailure::from)?;
                Ok(json!({ "locked": true }))
            }
            _ => self.runtime.execute_provider(call),
        }
    }

    fn provider_binding(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        now_unix_ms: u64,
    ) -> Result<ProviderBinding, ServiceFailure> {
        let permission = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        Ok(ProviderBinding {
            authority_handle,
            authority_revision,
            wallet_session_id: self.provider.wallet_session_id(),
            permission_generation: permission.generation,
        })
    }

    fn supported_provider_methods(&self) -> BTreeSet<ProviderMethod> {
        if !self
            .capabilities
            .contains(&ServiceCapability::ProviderDispatch)
        {
            return BTreeSet::new();
        }
        ProviderMethod::ALL
            .into_iter()
            .filter(|method| {
                if matches!(
                    method,
                    ProviderMethod::HnsRequestAccounts | ProviderMethod::HnsAccounts
                ) {
                    return self
                        .runtime
                        .supports_provider_method(ProviderMethod::HnsRequestAccounts);
                }
                if *method == ProviderMethod::WalletLock
                    && !self
                        .capabilities
                        .contains(&ServiceCapability::WalletOperations)
                {
                    return false;
                }
                if method.approval().is_some_and(value_movement_approval)
                    && !self
                        .capabilities
                        .contains(&ServiceCapability::ValueMovement)
                {
                    return false;
                }
                service_owned_method(*method) || self.runtime.supports_provider_method(*method)
            })
            .collect()
    }

    fn supported_provider_method_names(&self) -> BTreeSet<String> {
        self.supported_provider_methods()
            .into_iter()
            .map(|method| method.wire_name().to_owned())
            .collect()
    }

    fn prune_pending(&mut self, now_unix: u64) {
        self.pending
            .retain(|_, pending| pending.expires_at_unix > now_unix);
    }

    fn approve_hns_account_grant(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        expected_permission_generation: u64,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        validate_empty_params(&call.params)?;
        if call.namespace != SelectedNamespace::Hns {
            return Err(invalid_request(
                "Handshake accounts require the HNS namespace",
            ));
        }
        if !self
            .runtime
            .supports_provider_method(ProviderMethod::HnsRequestAccounts)
        {
            return Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ));
        }
        let account = self.runtime.prepare_hns_account_grant(call)?;
        validate_hns_account_summary(&account)?;
        let account_id = account.account_id;
        let value = json!([account_id.to_string()]);
        if serde_json::to_vec(&value)
            .map_err(|_| invalid_request("account result encoding failed"))?
            .len()
            > MAX_PROVIDER_RESULT_BYTES
        {
            return Err(invalid_request("account result exceeds the provider bound"));
        }
        let permission = self
            .provider
            .grant_scoped_permissions_at_generation(
                authority_handle,
                authority_revision,
                expected_permission_generation,
                BTreeSet::from([PermissionCapability::Accounts]),
                BTreeSet::from([account_id]),
                BTreeSet::new(),
                now_unix_ms,
                None,
            )
            .map_err(provider_failure)?;
        if permission.approved_accounts != BTreeSet::from([account_id]) {
            return Err(provider_failure(ProviderError::Persistence));
        }
        self.pending.clear();
        self.event_sequences.clear();
        Ok(value)
    }

    fn approved_hns_accounts(
        &mut self,
        authority_handle: HostAuthorityHandleId,
        authority_revision: u64,
        call: &ApprovedCall,
        now_unix_ms: u64,
    ) -> Result<Value, ServiceFailure> {
        validate_empty_params(&call.params)?;
        if call.namespace != SelectedNamespace::Hns {
            return Err(invalid_request(
                "Handshake accounts require the HNS namespace",
            ));
        }
        let permission = self
            .provider
            .permission_snapshot(authority_handle, authority_revision, now_unix_ms)
            .map_err(provider_failure)?;
        let record = permission
            .record
            .ok_or_else(|| provider_failure(ProviderError::Unauthorized))?;
        if !record
            .capabilities
            .contains(&PermissionCapability::Accounts)
            || record.approved_accounts.is_empty()
        {
            return Err(provider_failure(ProviderError::Unauthorized));
        }
        Ok(Value::Array(
            record
                .approved_accounts
                .iter()
                .map(|account| Value::String(account.to_string()))
                .collect(),
        ))
    }
}

impl<R: ServiceRuntime> WalletService<WalletStore, R> {
    pub fn new_persistent(store: WalletStore, runtime: R) -> Result<Self, ServiceError> {
        Self::new(store, runtime, true)
    }
}

fn provider_authority(
    authority: HostAuthorityFacts,
) -> Result<HostAuthorityRegistration, ServiceFailure> {
    Ok(HostAuthorityRegistration {
        origin: Origin::parse(&authority.origin).map_err(provider_failure)?,
        namespace: match authority.namespace {
            ProviderNamespace::Hns => SelectedNamespace::Hns,
            ProviderNamespace::Icann => SelectedNamespace::Icann,
        },
        runtime_session: authority.runtime_session_id,
        runtime_generation: authority.runtime_generation,
        policy_generation: authority.policy_generation,
        navigation_generation: authority.navigation_generation,
        decision_fingerprint: authority.decision_fingerprint,
        valid_until_unix_ms: authority.valid_until_unix_ms,
    })
}

fn service_owned_method(method: ProviderMethod) -> bool {
    matches!(
        method,
        ProviderMethod::WalletGetCapabilities
            | ProviderMethod::WalletRequestPermissions
            | ProviderMethod::WalletGetPermissions
            | ProviderMethod::WalletRevokePermissions
            | ProviderMethod::HnsAccounts
            | ProviderMethod::WalletLock
    )
}

fn value_movement_approval(kind: ApprovalKind) -> bool {
    matches!(
        kind,
        ApprovalKind::Send
            | ApprovalKind::NameTransfer
            | ApprovalKind::NameFinalize
            | ApprovalKind::NameMarketOffer
            | ApprovalKind::NameMarketPurchase
            | ApprovalKind::MarketIntent
            | ApprovalKind::FillAcceptance
            | ApprovalKind::SwapRedeem
            | ApprovalKind::SwapRefund
    )
}

fn requested_capabilities(
    call: &ApprovedCall,
) -> Result<BTreeSet<PermissionCapability>, ServiceFailure> {
    if call.method == ProviderMethod::HnsRequestAccounts {
        return Ok(BTreeSet::from([PermissionCapability::Accounts]));
    }
    let value = call
        .params
        .get("capabilities")
        .or_else(|| call.params.get("scopes"))
        .cloned()
        .ok_or_else(|| invalid_request("permission capabilities are required"))?;
    let capabilities: BTreeSet<PermissionCapability> = serde_json::from_value(value)
        .map_err(|_| invalid_request("permission capabilities are invalid"))?;
    if capabilities.is_empty() {
        return Err(invalid_request("permission capabilities are empty"));
    }
    if capabilities.contains(&PermissionCapability::Accounts) {
        return Err(invalid_request(
            "Accounts permission requires hns_requestAccounts",
        ));
    }
    Ok(capabilities)
}

fn validate_empty_params(params: &Value) -> Result<(), ServiceFailure> {
    if params.is_null() || params.as_object().is_some_and(|object| object.is_empty()) {
        Ok(())
    } else {
        Err(invalid_request("method does not accept parameters"))
    }
}

fn validate_hns_account_summary(account: &AccountSummary) -> Result<(), ServiceFailure> {
    let valid_receive = account.receive_display.as_ref().is_none_or(|value| {
        !value.is_empty() && value.len() <= MAX_PUBLIC_STRING_BYTES && value.is_ascii()
    });
    if account.module != ModuleId::Handshake
        || account.account_id.as_bytes().iter().all(|byte| *byte == 0)
        || account.label.is_empty()
        || account.label.len() > MAX_PUBLIC_STRING_BYTES
        || !account.label.is_ascii()
        || !valid_receive
    {
        return Err(invalid_request("runtime returned an invalid HNS account"));
    }
    Ok(())
}

fn requested_module(params: &Value) -> Result<ModuleId, ServiceFailure> {
    serde_json::from_value(
        params
            .get("module")
            .cloned()
            .ok_or_else(|| invalid_request("module is required"))?,
    )
    .map_err(|_| invalid_request("module is invalid"))
}

fn validate_approval_summary(
    call: &ApprovedCall,
    summary: &ApprovalSummary,
) -> Result<(), ServiceFailure> {
    let ApprovalSummary::Send {
        amount,
        maximum_fee,
        chain,
        ..
    } = summary
    else {
        if matches!(call.method, ProviderMethod::HnsSend | ProviderMethod::AssetSend) {
            return Err(invalid_request("send approval summary is mismatched"));
        }
        return Ok(());
    };

    let expected_chain = match call.method {
        ProviderMethod::HnsSend => ModuleId::Handshake,
        ProviderMethod::AssetSend => {
            let module = requested_module(&call.params)?;
            if !matches!(module, ModuleId::Bitcoin | ModuleId::Ethereum) {
                return Err(invalid_request("external send module is invalid"));
            }
            module
        }
        _ => return Ok(()),
    };
    if *chain != expected_chain
        || amount.asset != expected_chain.asset()
        || maximum_fee.asset != expected_chain.asset()
    {
        return Err(invalid_request(
            "send approval asset or chain is mismatched",
        ));
    }
    Ok(())
}

fn permission_value(permission: PermissionSnapshot) -> Result<Value, ServiceFailure> {
    let Some(record) = permission.record else {
        return Ok(json!({
            "permissionGeneration": permission.generation,
            "capabilities": [],
            "accounts": []
        }));
    };
    let origin = record.origin.as_str().to_owned();
    let capabilities = record.capabilities;
    let accounts = record
        .approved_accounts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    Ok(json!({
        "origin": origin,
        "permissionGeneration": permission.generation,
        "capabilities": capabilities,
        "accounts": accounts,
        "expiresAtUnix": record.expires_at_unix,
    }))
}

fn wire_approval_id(id: ApprovalId) -> Result<ProviderApprovalId, ServiceFailure> {
    ProviderApprovalId::from_bytes(id.into_bytes())
        .map_err(|_| invalid_request("approval identifier is invalid"))
}

fn random_service_session() -> Result<WalletServiceSessionId, ServiceError> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ServiceError::Randomness)?;
        if let Ok(id) = WalletServiceSessionId::from_bytes(bytes) {
            return Ok(id);
        }
    }
}

fn random_wallet_session() -> Result<WalletSessionId, ServiceError> {
    loop {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ServiceError::Randomness)?;
        if let Ok(id) = WalletSessionId::from_bytes(bytes) {
            return Ok(id);
        }
    }
}

fn invalid_request(message: &str) -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::InvalidRequest,
        message: message.to_owned(),
        unsupported_capability: None,
    }
}

fn stale_approval() -> ServiceFailure {
    ServiceFailure {
        code: ServiceErrorCode::ApprovalStale,
        message: "approval is stale, expired, or belongs to another authority".to_owned(),
        unsupported_capability: None,
    }
}

fn provider_failure(error: ProviderError) -> ServiceFailure {
    let code = match error {
        ProviderError::AuthorityNotFound => ServiceErrorCode::AuthorityUnknown,
        ProviderError::DuplicateAuthority
        | ProviderError::AuthorityCapacity
        | ProviderError::StaleContext
        | ProviderError::ClockRollback => ServiceErrorCode::AuthorityStale,
        ProviderError::Unauthorized => ServiceErrorCode::PermissionDenied,
        ProviderError::WalletLocked => ServiceErrorCode::WalletLocked,
        ProviderError::RateLimited => ServiceErrorCode::RateLimited,
        ProviderError::Replay => ServiceErrorCode::Replay,
        ProviderError::StaleApproval => ServiceErrorCode::ApprovalStale,
        ProviderError::Persistence => ServiceErrorCode::PersistenceFailure,
        _ => ServiceErrorCode::InvalidRequest,
    };
    ServiceFailure {
        code,
        message: error.to_string(),
        unsupported_capability: None,
    }
}

impl From<ServiceError> for ServiceFailure {
    fn from(error: ServiceError) -> Self {
        Self {
            code: ServiceErrorCode::RuntimeFailure,
            message: error.to_string(),
            unsupported_capability: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("wallet service ABI rejected a frame: {0}")]
    Abi(#[from] hns_wallet_ffi::AbiError),
    #[error("provider authority or state rejected an operation: {0}")]
    Provider(#[from] ProviderError),
    #[error("host must negotiate a private service session first")]
    HandshakeRequired,
    #[error("wallet service session was already negotiated")]
    AlreadyNegotiated,
    #[error("host, service, or restart session does not match")]
    SessionMismatch,
    #[error("host channel sequence mismatch: expected {expected}, received {received}")]
    SequenceMismatch { expected: u64, received: u64 },
    #[error("request identifier was already consumed")]
    DuplicateRequest,
    #[error("channel or event sequence is exhausted")]
    SequenceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_wallet_ffi::{HostHello, decode_service_frame, encode_host_frame};
    use hns_wallet_provider::MemoryProviderState;
    use hns_wallet_types::{AccountId, BrowserRuntimeSessionId, ProviderAuthorityFingerprint};

    const NOW_MS: u64 = 100_000;

    #[derive(Default)]
    struct ProviderRuntime;

    impl ServiceRuntime for ProviderRuntime {
        fn capabilities(&self) -> BTreeSet<ServiceCapability> {
            BTreeSet::from([ServiceCapability::ProviderDispatch])
        }

        fn supports_provider_method(&self, _: ProviderMethod) -> bool {
            false
        }

        fn prepare_approval(
            &mut self,
            _: &PendingApproval,
        ) -> Result<ApprovalSummary, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }

        fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }
    }

    struct AccountRuntime {
        account: AccountSummary,
        account_join_available: bool,
    }

    impl ServiceRuntime for AccountRuntime {
        fn capabilities(&self) -> BTreeSet<ServiceCapability> {
            BTreeSet::from([ServiceCapability::ProviderDispatch])
        }

        fn supports_provider_method(&self, method: ProviderMethod) -> bool {
            self.account_join_available && method == ProviderMethod::HnsRequestAccounts
        }

        fn prepare_approval(
            &mut self,
            _: &PendingApproval,
        ) -> Result<ApprovalSummary, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn prepare_hns_account_grant(
            &mut self,
            _: &ApprovedCall,
        ) -> Result<AccountSummary, ServiceFailure> {
            Ok(self.account.clone())
        }

        fn execute_provider(&mut self, _: ApprovedCall) -> Result<Value, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::ProviderDispatch,
            ))
        }

        fn lock_wallet(&mut self) -> Result<(), ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }

        fn execute_wallet(&mut self, _: WalletRequest) -> Result<WalletResponse, ServiceFailure> {
            Err(ServiceFailure::unsupported(
                ServiceCapability::WalletOperations,
            ))
        }
    }

    fn host_session() -> HostSessionId {
        HostSessionId::from_bytes([1_u8; 32]).expect("host session")
    }

    fn handle() -> HostAuthorityHandleId {
        HostAuthorityHandleId::from_bytes([2_u8; 32]).expect("handle")
    }

    fn registration() -> HostAuthorityRegistration {
        HostAuthorityRegistration {
            origin: Origin::parse("https://wallet.example").expect("origin"),
            namespace: SelectedNamespace::Hns,
            runtime_session: BrowserRuntimeSessionId::from_bytes([3_u8; 16])
                .expect("runtime session"),
            runtime_generation: 1,
            policy_generation: 1,
            navigation_generation: 1,
            decision_fingerprint: ProviderAuthorityFingerprint::from_bytes([4_u8; 32])
                .expect("fingerprint"),
            valid_until_unix_ms: NOW_MS + 60_000,
        }
    }

    fn provider_service() -> WalletService<MemoryProviderState, ProviderRuntime> {
        let mut service =
            WalletService::new_ephemeral(MemoryProviderState::default(), ProviderRuntime)
                .expect("service");
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        service
    }

    fn account_service() -> WalletService<MemoryProviderState, AccountRuntime> {
        let mut service = WalletService::new_ephemeral(
            MemoryProviderState::default(),
            AccountRuntime {
                account: AccountSummary {
                    account_id: AccountId::new([9_u8; 16]),
                    module: ModuleId::Handshake,
                    label: "Handshake".to_owned(),
                    receive_display: None,
                },
                account_join_available: true,
            },
        )
        .expect("service");
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        service
            .provider
            .set_wallet_state(service.wallet_session_id, false);
        service
    }

    fn hello() -> zeroize::Zeroizing<Vec<u8>> {
        encode_host_frame(&HostFrame::Hello {
            hello: HostHello {
                protocol_version: WALLET_ABI_VERSION,
                platform: hns_wallet_ffi::HostPlatform::ChromiumNativeHost,
                host_session_id: host_session(),
                restart_generation: 1,
            },
        })
        .expect("hello")
    }

    #[test]
    fn default_subprocess_never_claims_provider_value_or_browser_availability() {
        let mut service = WalletService::new_ephemeral(
            MemoryProviderState::default(),
            UnavailableRuntime,
        )
        .expect("service");
        let response = service.process_frame(&hello(), 1).expect("hello response");
        let ServiceFrame::Hello { hello } = decode_service_frame(&response).expect("decode") else {
            panic!("expected hello")
        };
        assert!(!hello.capabilities.contains(&ServiceCapability::ProviderDispatch));
        assert!(!hello.capabilities.contains(&ServiceCapability::ValueMovement));
        assert!(!hello.capabilities.contains(&ServiceCapability::BrowserIntegration));
        service
            .provider
            .register_authority(handle(), registration(), NOW_MS)
            .expect("authority");
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("private capability snapshot")
        else {
            panic!("private capabilities")
        };
        assert!(capabilities.methods.is_empty());
    }

    #[test]
    fn a_new_service_process_rotates_sessions_and_drops_ephemeral_state() {
        let first = WalletService::new_ephemeral(
            MemoryProviderState::default(),
            UnavailableRuntime,
        )
        .expect("first");
        let second = WalletService::new_ephemeral(
            MemoryProviderState::default(),
            UnavailableRuntime,
        )
        .expect("second");
        assert_ne!(first.service_session_id, second.service_session_id);
        assert!(second.pending.is_empty());
        assert!(second.event_sequences.is_empty());
        assert!(second.seen_request_ids.is_empty());
    }

    #[test]
    fn private_provider_capabilities_are_typed_exact_and_bound() {
        let mut service = provider_service();
        let response = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("capabilities");
        let ServiceResponse::ProviderCapabilities {
            binding,
            capabilities: snapshot,
        } = response
        else {
            panic!("private capabilities")
        };
        assert_eq!(binding.wallet_session_id, service.wallet_session_id);
        assert_eq!(binding.permission_generation, 0);
        assert_eq!(snapshot.provider_schema_version, 1);
        assert_eq!(snapshot.approval_schema_version, 2);
        assert_eq!(snapshot.permission_generation, 0);
        assert!(!snapshot.methods.contains("hns_requestAccounts"));
        assert_eq!(
            snapshot.methods,
            BTreeSet::from([
                "wallet_getCapabilities".to_owned(),
                "wallet_getPermissions".to_owned(),
                "wallet_requestPermissions".to_owned(),
                "wallet_revokePermissions".to_owned(),
            ])
        );
    }

    #[test]
    fn canonical_provider_account_join_persists_and_projects_only_the_approved_account() {
        let mut service = account_service();
        let ServiceResponse::ProviderCapabilities { capabilities, .. } = service
            .provider_capabilities(handle(), 1, NOW_MS)
            .expect("capabilities")
        else {
            panic!("private capabilities")
        };
        assert!(capabilities.methods.contains("hns_requestAccounts"));
        assert!(capabilities.methods.contains("hns_accounts"));

        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("account request")
        else {
            panic!("approval")
        };
        assert_eq!(
            approval.summary,
            ApprovalSummary::Permissions {
                capabilities: BTreeSet::from([PermissionCapability::Accounts]),
            }
        );

        let ServiceResponse::ProviderResult { binding, value } = service
            .approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 1,
            )
            .expect("approved account join")
        else {
            panic!("account result")
        };
        let account = AccountId::new([9_u8; 16]);
        assert_eq!(binding.permission_generation, 1);
        assert_eq!(value, json!([account.to_string()]));
        let permission = service
            .provider
            .permission(handle(), 1, NOW_MS + 1)
            .expect("permission")
            .expect("grant");
        assert_eq!(permission.approved_accounts, BTreeSet::from([account]));

        let ServiceResponse::ProviderResult { binding, value } = service
            .provider_request(
                handle(),
                1,
                2,
                ProviderMethod::HnsAccounts.wire_name().to_owned(),
                Value::Object(serde_json::Map::new()),
                NOW_MS + 2,
            )
            .expect("account projection")
        else {
            panic!("account projection")
        };
        assert_eq!(binding.permission_generation, 1);
        assert_eq!(value, json!([account.to_string()]));

        service.runtime.account_join_available = false;
        let failure = service.provider_request(
            handle(),
            1,
            3,
            ProviderMethod::HnsAccounts.wire_name().to_owned(),
            Value::Null,
            NOW_MS + 3,
        );
        assert!(matches!(
            failure,
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));

        let failure = service.provider_request(
            handle(),
            1,
            4,
            ProviderMethod::WalletRequestPermissions
                .wire_name()
                .to_owned(),
            json!({ "capabilities": ["accounts"] }),
            NOW_MS + 4,
        );
        assert!(matches!(
            failure,
            Err(ServiceFailure {
                code: ServiceErrorCode::InvalidRequest,
                ..
            })
        ));
    }

    #[test]
    fn canonical_provider_account_join_rechecks_runtime_when_approval_executes() {
        let mut service = account_service();
        let ServiceResponse::ApprovalRequired { approval } = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::HnsRequestAccounts.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("account request")
        else {
            panic!("approval")
        };
        service.runtime.account_join_available = false;
        assert!(matches!(
            service.approval_decision(
                handle(),
                1,
                approval.approval_id,
                hns_wallet_ffi::ApprovalDecision::Approve,
                NOW_MS + 1,
            ),
            Err(ServiceFailure {
                code: ServiceErrorCode::UnsupportedCapability,
                ..
            })
        ));
        let permission = service
            .provider
            .permission_snapshot(handle(), 1, NOW_MS + 1)
            .expect("permission snapshot");
        assert_eq!(permission.generation, 0);
        assert!(permission.record.is_none());
    }

    #[test]
    fn website_capabilities_expose_only_public_api_version_and_methods() {
        let mut service = provider_service();
        let response = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::WalletGetCapabilities.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("website capabilities");
        let ServiceResponse::ProviderResult { binding, value } = response else {
            panic!("provider result")
        };
        assert_eq!(binding.permission_generation, 0);
        assert_eq!(
            value.as_object().expect("object").keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from(["methods".to_owned(), "providerApiVersion".to_owned()])
        );
        assert_eq!(value["providerApiVersion"], json!(1));
    }

    #[test]
    fn get_permissions_returns_the_revocation_tombstone_generation() {
        let mut service = provider_service();
        service
            .provider
            .set_wallet_state(service.wallet_session_id, false);
        service
            .provider
            .grant_permissions(
                handle(),
                1,
                BTreeSet::from([PermissionCapability::Send]),
                BTreeSet::new(),
                NOW_MS,
                None,
            )
            .expect("grant");
        assert_eq!(
            service
                .provider
                .revoke_permissions(handle(), 1, NOW_MS)
                .expect("revoke"),
            2
        );
        let response = service
            .provider_request(
                handle(),
                1,
                1,
                ProviderMethod::WalletGetPermissions.wire_name().to_owned(),
                Value::Null,
                NOW_MS,
            )
            .expect("permissions");
        let ServiceResponse::ProviderResult {
            binding,
            value,
        } = response
        else {
            panic!("provider result")
        };
        assert_eq!(binding.permission_generation, 2);
        assert_eq!(value["permissionGeneration"], json!(2));
        assert_eq!(value["capabilities"], json!([]));
    }
}
