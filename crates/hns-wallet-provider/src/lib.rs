#![doc = "Hostile-page request, permission, approval, and event policy core."]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{ApprovalId, ApprovalKind, PermissionCapability};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const MAX_PROVIDER_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_METHOD_BYTES: usize = 96;
pub const MAX_ORIGIN_BYTES: usize = 512;
pub const APPROVAL_LIFETIME_SECONDS: u64 = 300;
pub const RATE_WINDOW_SECONDS: u64 = 60;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Origin {
    serialized: String,
}

impl Origin {
    pub fn parse(input: &str) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > MAX_ORIGIN_BYTES || !input.is_ascii() {
            return Err(ProviderError::InvalidOrigin);
        }
        let parsed = Url::parse(input).map_err(|_| ProviderError::InvalidOrigin)?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(ProviderError::InvalidOrigin);
        }
        let host = parsed.host_str().ok_or(ProviderError::InvalidOrigin)?;
        let secure = parsed.scheme() == "https"
            || (parsed.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1"));
        if !secure {
            return Err(ProviderError::InsecureContext);
        }
        let port = parsed
            .port_or_known_default()
            .ok_or(ProviderError::InvalidOrigin)?;
        let default_port = (parsed.scheme() == "https" && port == 443)
            || (parsed.scheme() == "http" && port == 80);
        let serialized = if default_port {
            format!("{}://{host}", parsed.scheme())
        } else {
            format!("{}://{host}:{port}", parsed.scheme())
        };
        Ok(Self { serialized })
    }

    pub fn as_str(&self) -> &str {
        &self.serialized
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectedNamespace {
    Hns,
    Icann,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityBinding {
    pub origin: Origin,
    pub namespace: SelectedNamespace,
    pub authenticated_context: bool,
    pub provider_injection_permitted: bool,
    pub browser_authority_session: u64,
    pub browser_authority_generation: u64,
    pub policy_generation: u64,
    pub wallet_session: u64,
    pub permission_generation: u64,
    pub navigation_generation: u64,
    pub wallet_locked: bool,
}

impl AuthorityBinding {
    pub fn validate(&self) -> Result<(), ProviderError> {
        if !self.authenticated_context || !self.provider_injection_permitted {
            return Err(ProviderError::InjectionDenied);
        }
        if self.browser_authority_session == 0
            || self.browser_authority_generation == 0
            || self.policy_generation == 0
            || self.wallet_session == 0
            || self.permission_generation == 0
            || self.navigation_generation == 0
        {
            return Err(ProviderError::StaleContext);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContext {
    pub origin: Origin,
    pub namespace: SelectedNamespace,
    pub browser_authority_session: u64,
    pub browser_authority_generation: u64,
    pub policy_generation: u64,
    pub wallet_session: u64,
    pub permission_generation: u64,
    pub navigation_generation: u64,
    pub request_nonce: u64,
    pub now_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl ProviderRequest {
    pub fn decode(input: &[u8]) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > MAX_PROVIDER_REQUEST_BYTES {
            return Err(ProviderError::RequestTooLarge);
        }
        let request: Self =
            serde_json::from_slice(input).map_err(|_| ProviderError::InvalidParams)?;
        if request.method.is_empty() || request.method.len() > MAX_METHOD_BYTES {
            return Err(ProviderError::MethodNotFound);
        }
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ProviderMethod {
    WalletGetCapabilities,
    WalletGetEnabledModules,
    WalletEnableModule,
    WalletDisableModule,
    WalletRequestPermissions,
    WalletGetPermissions,
    WalletRevokePermissions,
    WalletLock,
    WalletGetStatus,
    HnsRequestAccounts,
    HnsAccounts,
    HnsGetBalance,
    HnsGetTransactions,
    HnsGetReceiveAddress,
    HnsSend,
    HnsGetNames,
    HnsGetName,
    HnsImportKnownName,
    HnsTransferName,
    HnsFinalizeName,
    HnsSignTypedMessage,
    AssetGetAccount,
    AssetGetBalance,
    AssetGetTransactions,
    AssetGetReceiveTarget,
    AssetSend,
    NameMarketListOffers,
    NameMarketCreateFixedPriceOffer,
    NameMarketCancelOffer,
    NameMarketAcceptOffer,
    NameMarketGetSession,
    NameMarketFinalizePurchase,
    NameMarketRecoverName,
    SwapGetSupportedPairs,
    SwapGetPriceRound,
    SwapListMarketIntents,
    SwapPublishMarketIntent,
    SwapCancelMarketIntent,
    SwapRequestMatch,
    SwapAcceptFill,
    SwapGetSession,
    SwapRedeem,
    SwapRefund,
}

impl ProviderMethod {
    pub fn parse(method: &str) -> Result<Self, ProviderError> {
        let parsed = match method {
            "wallet_getCapabilities" => Self::WalletGetCapabilities,
            "wallet_getEnabledModules" => Self::WalletGetEnabledModules,
            "wallet_enableModule" => Self::WalletEnableModule,
            "wallet_disableModule" => Self::WalletDisableModule,
            "wallet_requestPermissions" => Self::WalletRequestPermissions,
            "wallet_getPermissions" => Self::WalletGetPermissions,
            "wallet_revokePermissions" => Self::WalletRevokePermissions,
            "wallet_lock" => Self::WalletLock,
            "wallet_getStatus" => Self::WalletGetStatus,
            "hns_requestAccounts" => Self::HnsRequestAccounts,
            "hns_accounts" => Self::HnsAccounts,
            "hns_getBalance" => Self::HnsGetBalance,
            "hns_getTransactions" => Self::HnsGetTransactions,
            "hns_getReceiveAddress" => Self::HnsGetReceiveAddress,
            "hns_send" => Self::HnsSend,
            "hns_getNames" => Self::HnsGetNames,
            "hns_getName" => Self::HnsGetName,
            "hns_importKnownName" => Self::HnsImportKnownName,
            "hns_transferName" => Self::HnsTransferName,
            "hns_finalizeName" => Self::HnsFinalizeName,
            "hns_signTypedMessage" => Self::HnsSignTypedMessage,
            "asset_getAccount" => Self::AssetGetAccount,
            "asset_getBalance" => Self::AssetGetBalance,
            "asset_getTransactions" => Self::AssetGetTransactions,
            "asset_getReceiveTarget" => Self::AssetGetReceiveTarget,
            "asset_send" => Self::AssetSend,
            "nameMarket_listOffers" => Self::NameMarketListOffers,
            "nameMarket_createFixedPriceOffer" => Self::NameMarketCreateFixedPriceOffer,
            "nameMarket_cancelOffer" => Self::NameMarketCancelOffer,
            "nameMarket_acceptOffer" => Self::NameMarketAcceptOffer,
            "nameMarket_getSession" => Self::NameMarketGetSession,
            "nameMarket_finalizePurchase" => Self::NameMarketFinalizePurchase,
            "nameMarket_recoverName" => Self::NameMarketRecoverName,
            "swap_getSupportedPairs" => Self::SwapGetSupportedPairs,
            "swap_getPriceRound" => Self::SwapGetPriceRound,
            "swap_listMarketIntents" => Self::SwapListMarketIntents,
            "swap_publishMarketIntent" => Self::SwapPublishMarketIntent,
            "swap_cancelMarketIntent" => Self::SwapCancelMarketIntent,
            "swap_requestMatch" => Self::SwapRequestMatch,
            "swap_acceptFill" => Self::SwapAcceptFill,
            "swap_getSession" => Self::SwapGetSession,
            "swap_redeem" => Self::SwapRedeem,
            "swap_refund" => Self::SwapRefund,
            method if FORBIDDEN_METHODS.contains(&method) => {
                return Err(ProviderError::ForbiddenMethod);
            }
            _ => return Err(ProviderError::MethodNotFound),
        };
        Ok(parsed)
    }

    pub const fn permission(self) -> Option<PermissionCapability> {
        match self {
            Self::WalletGetCapabilities
            | Self::WalletGetEnabledModules
            | Self::WalletRequestPermissions
            | Self::WalletGetPermissions
            | Self::WalletRevokePermissions
            | Self::WalletLock
            | Self::WalletGetStatus
            | Self::HnsRequestAccounts
            | Self::SwapGetSupportedPairs => None,
            Self::HnsAccounts | Self::AssetGetAccount => Some(PermissionCapability::Accounts),
            Self::HnsGetBalance | Self::AssetGetBalance => Some(PermissionCapability::Balance),
            Self::HnsGetTransactions | Self::AssetGetTransactions => {
                Some(PermissionCapability::Transactions)
            }
            Self::HnsGetReceiveAddress | Self::AssetGetReceiveTarget => {
                Some(PermissionCapability::ReceiveTarget)
            }
            Self::HnsSend | Self::AssetSend => Some(PermissionCapability::Send),
            Self::HnsGetNames | Self::HnsGetName | Self::HnsImportKnownName => {
                Some(PermissionCapability::Names)
            }
            Self::HnsTransferName => Some(PermissionCapability::NameTransfer),
            Self::HnsFinalizeName => Some(PermissionCapability::NameFinalize),
            Self::HnsSignTypedMessage => Some(PermissionCapability::TypedIdentitySignature),
            Self::NameMarketListOffers
            | Self::NameMarketCreateFixedPriceOffer
            | Self::NameMarketCancelOffer
            | Self::NameMarketAcceptOffer
            | Self::NameMarketGetSession
            | Self::NameMarketFinalizePurchase
            | Self::NameMarketRecoverName => Some(PermissionCapability::NameMarket),
            Self::SwapGetPriceRound
            | Self::SwapListMarketIntents
            | Self::SwapPublishMarketIntent
            | Self::SwapCancelMarketIntent
            | Self::SwapRequestMatch
            | Self::SwapAcceptFill => Some(PermissionCapability::CrossChainMarket),
            Self::SwapGetSession | Self::SwapRedeem | Self::SwapRefund => {
                Some(PermissionCapability::SwapSettlement)
            }
            Self::WalletEnableModule | Self::WalletDisableModule => None,
        }
    }

    pub const fn approval(self) -> Option<ApprovalKind> {
        match self {
            Self::WalletEnableModule | Self::WalletDisableModule => {
                Some(ApprovalKind::ModuleEnablement)
            }
            Self::WalletRequestPermissions | Self::HnsRequestAccounts => {
                Some(ApprovalKind::Permission)
            }
            Self::HnsSend | Self::AssetSend => Some(ApprovalKind::Send),
            Self::HnsTransferName => Some(ApprovalKind::NameTransfer),
            Self::HnsFinalizeName => Some(ApprovalKind::NameFinalize),
            Self::HnsSignTypedMessage => Some(ApprovalKind::TypedSignature),
            Self::NameMarketCreateFixedPriceOffer | Self::NameMarketCancelOffer => {
                Some(ApprovalKind::NameMarketOffer)
            }
            Self::NameMarketAcceptOffer | Self::NameMarketFinalizePurchase => {
                Some(ApprovalKind::NameMarketPurchase)
            }
            Self::NameMarketRecoverName => Some(ApprovalKind::NameMarketOffer),
            Self::SwapPublishMarketIntent | Self::SwapCancelMarketIntent => {
                Some(ApprovalKind::MarketIntent)
            }
            Self::SwapRequestMatch | Self::SwapAcceptFill => Some(ApprovalKind::FillAcceptance),
            Self::SwapRedeem => Some(ApprovalKind::SwapRedeem),
            Self::SwapRefund => Some(ApprovalKind::SwapRefund),
            _ => None,
        }
    }

    const fn rate_limit(self) -> u32 {
        if self.approval().is_some() { 10 } else { 120 }
    }
}

const FORBIDDEN_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_call",
    "eth_estimateGas",
    "eth_sign",
    "personal_sign",
    "wallet_addEthereumChain",
    "wallet_switchEthereumChain",
    "bitcoin_signPsbt",
    "signRawTransaction",
    "wallet_getSeed",
    "wallet_getPrivateKey",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PermissionRecord {
    pub origin: Origin,
    pub generation: u64,
    pub capabilities: BTreeSet<PermissionCapability>,
    pub approved_names: BTreeSet<[u8; 32]>,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

impl PermissionRecord {
    fn permits(&self, capability: PermissionCapability, now_unix: u64) -> bool {
        self.capabilities.contains(&capability)
            && self.expires_at_unix.is_none_or(|expiry| expiry > now_unix)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovedCall {
    pub origin: Origin,
    pub method: ProviderMethod,
    pub params: Value,
    pub request_nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: ApprovalId,
    pub kind: ApprovalKind,
    pub call: ApprovedCall,
    pub browser_authority_session: u64,
    pub browser_authority_generation: u64,
    pub policy_generation: u64,
    pub wallet_session: u64,
    pub permission_generation: u64,
    pub navigation_generation: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProviderAction {
    Execute(ApprovedCall),
    ApprovalRequired(PendingApproval),
}

pub trait ProviderStateStore {
    fn permission(&self, origin: &Origin) -> Result<Option<PermissionRecord>, ProviderError>;
    fn save_permission(&mut self, record: &PermissionRecord) -> Result<(), ProviderError>;
    fn revoke_permission(
        &mut self,
        origin: &Origin,
        expected_generation: u64,
        next_generation: u64,
        now_unix: u64,
    ) -> Result<(), ProviderError>;
    fn consume_nonce(
        &mut self,
        origin: &Origin,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), ProviderError>;
    fn save_pending(
        &mut self,
        approval: &PendingApproval,
        now_unix: u64,
    ) -> Result<(), ProviderError>;
}

impl ProviderStateStore for WalletStore {
    fn permission(&self, origin: &Origin) -> Result<Option<PermissionRecord>, ProviderError> {
        self.provider_permission(origin.as_str())?
            .map(|(_, bytes)| serde_json::from_slice(&bytes).map_err(ProviderError::from))
            .transpose()
    }

    fn save_permission(&mut self, record: &PermissionRecord) -> Result<(), ProviderError> {
        self.put_provider_permission(
            record.origin.as_str(),
            record.generation,
            &serde_json::to_vec(record)?,
            record.created_at_unix,
        )?;
        Ok(())
    }

    fn revoke_permission(
        &mut self,
        origin: &Origin,
        expected_generation: u64,
        next_generation: u64,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        self.revoke_provider_permission(
            origin.as_str(),
            expected_generation,
            next_generation,
            now_unix,
        )?;
        Ok(())
    }

    fn consume_nonce(
        &mut self,
        origin: &Origin,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), ProviderError> {
        self.consume_replay_nonce(origin.as_str(), nonce, now_unix, expires_at_unix)?;
        Ok(())
    }

    fn save_pending(
        &mut self,
        approval: &PendingApproval,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        self.put_pending_approval(
            approval.id,
            approval.call.origin.as_str(),
            &serde_json::to_vec(approval)?,
            now_unix,
            approval.expires_at_unix,
        )?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryProviderState {
    permissions: BTreeMap<Origin, PermissionRecord>,
    permission_generations: BTreeMap<Origin, u64>,
    nonces: BTreeMap<(Origin, u64), u64>,
    pending: BTreeMap<ApprovalId, PendingApproval>,
}

impl ProviderStateStore for MemoryProviderState {
    fn permission(&self, origin: &Origin) -> Result<Option<PermissionRecord>, ProviderError> {
        Ok(self.permissions.get(origin).cloned())
    }

    fn save_permission(&mut self, record: &PermissionRecord) -> Result<(), ProviderError> {
        let expected = match self.permission_generations.get(&record.origin).copied() {
            Some(current) => current.checked_add(1).ok_or(ProviderError::StaleContext)?,
            None => record.generation,
        };
        if record.generation != expected {
            return Err(ProviderError::StaleContext);
        }
        self.permission_generations
            .insert(record.origin.clone(), record.generation);
        self.permissions
            .insert(record.origin.clone(), record.clone());
        Ok(())
    }

    fn revoke_permission(
        &mut self,
        origin: &Origin,
        expected_generation: u64,
        next_generation: u64,
        _: u64,
    ) -> Result<(), ProviderError> {
        if self.permission_generations.get(origin).copied() != Some(expected_generation)
            || next_generation
                != expected_generation
                    .checked_add(1)
                    .ok_or(ProviderError::StaleContext)?
        {
            return Err(ProviderError::StaleContext);
        }
        self.permissions.remove(origin);
        self.permission_generations
            .insert(origin.clone(), next_generation);
        Ok(())
    }

    fn consume_nonce(
        &mut self,
        origin: &Origin,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), ProviderError> {
        self.nonces.retain(|_, expiry| *expiry > now_unix);
        if self
            .nonces
            .insert((origin.clone(), nonce), expires_at_unix)
            .is_some()
        {
            return Err(ProviderError::Replay);
        }
        Ok(())
    }

    fn save_pending(&mut self, approval: &PendingApproval, _: u64) -> Result<(), ProviderError> {
        self.pending.insert(approval.id, approval.clone());
        Ok(())
    }
}

pub struct ProviderCore<S> {
    binding: AuthorityBinding,
    state: S,
    pending: BTreeMap<ApprovalId, PendingApproval>,
    rate: BTreeMap<(Origin, ProviderMethod), RateWindow>,
}

impl<S: ProviderStateStore> ProviderCore<S> {
    pub fn new(binding: AuthorityBinding, state: S) -> Result<Self, ProviderError> {
        binding.validate()?;
        Ok(Self {
            binding,
            state,
            pending: BTreeMap::new(),
            rate: BTreeMap::new(),
        })
    }

    pub fn update_binding(&mut self, binding: AuthorityBinding) -> Result<(), ProviderError> {
        binding.validate()?;

        let same_authority_session = binding.origin == self.binding.origin
            && binding.namespace == self.binding.namespace
            && binding.browser_authority_session == self.binding.browser_authority_session
            && binding.wallet_session == self.binding.wallet_session;
        if same_authority_session
            && (binding.browser_authority_generation < self.binding.browser_authority_generation
                || binding.policy_generation < self.binding.policy_generation
                || binding.permission_generation < self.binding.permission_generation
                || binding.navigation_generation < self.binding.navigation_generation)
        {
            return Err(ProviderError::StaleContext);
        }

        let context_changed = binding != self.binding;
        let session_changed = binding.origin != self.binding.origin
            || binding.namespace != self.binding.namespace
            || binding.browser_authority_session != self.binding.browser_authority_session
            || binding.wallet_session != self.binding.wallet_session;
        if context_changed {
            self.pending.clear();
        }
        if session_changed {
            self.rate.clear();
        }
        self.binding = binding;
        Ok(())
    }

    pub fn request(
        &mut self,
        context: &RequestContext,
        request_bytes: &[u8],
    ) -> Result<ProviderAction, ProviderError> {
        let request = ProviderRequest::decode(request_bytes)?;
        self.validate_context(context)?;
        let method = ProviderMethod::parse(&request.method)?;
        validate_module_params(method, &request.params)?;
        self.enforce_rate(context, method)?;
        let replay_expiry = context
            .now_unix
            .checked_add(APPROVAL_LIFETIME_SECONDS)
            .ok_or(ProviderError::StaleContext)?;
        self.state.consume_nonce(
            &context.origin,
            context.request_nonce,
            context.now_unix,
            replay_expiry,
        )?;

        if self.binding.wallet_locked
            && !matches!(
                method,
                ProviderMethod::WalletGetStatus | ProviderMethod::WalletGetCapabilities
            )
        {
            return Err(ProviderError::WalletLocked);
        }
        if let Some(required) = method.permission() {
            let permission = self
                .state
                .permission(&context.origin)?
                .ok_or(ProviderError::Unauthorized)?;
            if permission.generation != context.permission_generation
                || !permission.permits(required, context.now_unix)
            {
                return Err(ProviderError::Unauthorized);
            }
        }

        let call = ApprovedCall {
            origin: context.origin.clone(),
            method,
            params: request.params,
            request_nonce: context.request_nonce,
        };
        let Some(kind) = method.approval() else {
            return Ok(ProviderAction::Execute(call));
        };
        let approval = PendingApproval {
            id: approval_id(context, method),
            kind,
            call,
            browser_authority_session: context.browser_authority_session,
            browser_authority_generation: context.browser_authority_generation,
            policy_generation: context.policy_generation,
            wallet_session: context.wallet_session,
            permission_generation: context.permission_generation,
            navigation_generation: context.navigation_generation,
            expires_at_unix: replay_expiry,
        };
        self.state.save_pending(&approval, context.now_unix)?;
        self.pending.insert(approval.id, approval.clone());
        Ok(ProviderAction::ApprovalRequired(approval))
    }

    pub fn approve(
        &mut self,
        context: &RequestContext,
        id: ApprovalId,
    ) -> Result<ApprovedCall, ProviderError> {
        self.validate_context(context)?;
        let approval = self
            .pending
            .remove(&id)
            .ok_or(ProviderError::StaleApproval)?;
        if approval.expires_at_unix <= context.now_unix
            || approval.call.origin != context.origin
            || approval.browser_authority_session != context.browser_authority_session
            || approval.browser_authority_generation != context.browser_authority_generation
            || approval.policy_generation != context.policy_generation
            || approval.wallet_session != context.wallet_session
            || approval.permission_generation != context.permission_generation
            || approval.navigation_generation != context.navigation_generation
        {
            return Err(ProviderError::StaleApproval);
        }
        Ok(approval.call)
    }

    pub fn grant_permissions(
        &mut self,
        origin: Origin,
        next_generation: u64,
        capabilities: BTreeSet<PermissionCapability>,
        approved_names: BTreeSet<[u8; 32]>,
        now_unix: u64,
        expires_at_unix: Option<u64>,
    ) -> Result<PermissionRecord, ProviderError> {
        if origin != self.binding.origin
            || next_generation
                != self
                    .binding
                    .permission_generation
                    .checked_add(1)
                    .ok_or(ProviderError::StaleContext)?
            || capabilities.is_empty()
            || expires_at_unix.is_some_and(|expiry| expiry <= now_unix)
        {
            return Err(ProviderError::InvalidPermission);
        }
        let record = PermissionRecord {
            origin,
            generation: next_generation,
            capabilities,
            approved_names,
            created_at_unix: now_unix,
            expires_at_unix,
        };
        self.state.save_permission(&record)?;
        self.binding.permission_generation = next_generation;
        Ok(record)
    }

    pub fn revoke_permissions(
        &mut self,
        origin: &Origin,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        if origin != &self.binding.origin {
            return Err(ProviderError::Unauthorized);
        }
        let expected_generation = self.binding.permission_generation;
        let next_generation = expected_generation
            .checked_add(1)
            .ok_or(ProviderError::StaleContext)?;
        self.state
            .revoke_permission(origin, expected_generation, next_generation, now_unix)?;
        self.pending.clear();
        self.binding.permission_generation = next_generation;
        Ok(())
    }

    fn validate_context(&self, context: &RequestContext) -> Result<(), ProviderError> {
        self.binding.validate()?;
        if context.request_nonce == 0
            || context.origin != self.binding.origin
            || context.namespace != self.binding.namespace
            || context.browser_authority_session != self.binding.browser_authority_session
            || context.browser_authority_generation != self.binding.browser_authority_generation
            || context.policy_generation != self.binding.policy_generation
            || context.wallet_session != self.binding.wallet_session
            || context.permission_generation != self.binding.permission_generation
            || context.navigation_generation != self.binding.navigation_generation
        {
            return Err(ProviderError::StaleContext);
        }
        Ok(())
    }

    fn enforce_rate(
        &mut self,
        context: &RequestContext,
        method: ProviderMethod,
    ) -> Result<(), ProviderError> {
        let key = (context.origin.clone(), method);
        let window = self.rate.entry(key).or_insert(RateWindow {
            starts_at_unix: context.now_unix,
            count: 0,
        });
        if context.now_unix.saturating_sub(window.starts_at_unix) >= RATE_WINDOW_SECONDS {
            *window = RateWindow {
                starts_at_unix: context.now_unix,
                count: 0,
            };
        }
        if window.count >= method.rate_limit() {
            return Err(ProviderError::RateLimited);
        }
        window.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RateWindow {
    starts_at_unix: u64,
    count: u32,
}

fn approval_id(context: &RequestContext, method: ProviderMethod) -> ApprovalId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-provider-approval/v1");
    hasher.update(context.origin.as_str().as_bytes());
    hasher.update(context.browser_authority_session.to_be_bytes());
    hasher.update(context.wallet_session.to_be_bytes());
    hasher.update(context.navigation_generation.to_be_bytes());
    hasher.update(context.request_nonce.to_be_bytes());
    hasher.update(format!("{method:?}").as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    ApprovalId::new(id)
}

fn validate_module_params(method: ProviderMethod, params: &Value) -> Result<(), ProviderError> {
    if !matches!(
        method,
        ProviderMethod::AssetGetAccount
            | ProviderMethod::AssetGetBalance
            | ProviderMethod::AssetGetTransactions
            | ProviderMethod::AssetGetReceiveTarget
            | ProviderMethod::AssetSend
    ) {
        return Ok(());
    }
    let module = params
        .as_object()
        .and_then(|object| object.get("module"))
        .and_then(Value::as_str)
        .ok_or(ProviderError::InvalidParams)?;
    if !matches!(module, "bitcoin" | "ethereum") {
        return Err(ProviderError::InvalidParams);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderEvent {
    Connect,
    Disconnect,
    PermissionsChanged,
    ModulesChanged,
    AccountsChanged,
    BalancesChanged,
    TransactionsChanged,
    NamesChanged,
    NameMarketChanged,
    PriceRoundChanged,
    MarketIntentChanged,
    SwapSessionChanged,
    WalletLocked,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid logical origin")]
    InvalidOrigin,
    #[error("provider requires an authenticated secure context")]
    InsecureContext,
    #[error("browser authority denied provider injection")]
    InjectionDenied,
    #[error("request context is stale or mismatched")]
    StaleContext,
    #[error("provider request exceeds its bounded maximum")]
    RequestTooLarge,
    #[error("provider method was not found")]
    MethodNotFound,
    #[error("method is intentionally forbidden")]
    ForbiddenMethod,
    #[error("provider parameters are invalid")]
    InvalidParams,
    #[error("origin lacks the required permission")]
    Unauthorized,
    #[error("wallet is locked")]
    WalletLocked,
    #[error("request rate limit exceeded")]
    RateLimited,
    #[error("request replay rejected")]
    Replay,
    #[error("approval is stale, expired, or belongs to another context")]
    StaleApproval,
    #[error("permission grant is invalid")]
    InvalidPermission,
    #[error("persistent provider state failed")]
    Persistence,
}

impl From<StoreError> for ProviderError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Replay => Self::Replay,
            _ => Self::Persistence,
        }
    }
}

impl From<serde_json::Error> for ProviderError {
    fn from(_: serde_json::Error) -> Self {
        Self::Persistence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin::parse("https://wallet.example").expect("origin")
    }

    fn binding() -> AuthorityBinding {
        AuthorityBinding {
            origin: origin(),
            namespace: SelectedNamespace::Hns,
            authenticated_context: true,
            provider_injection_permitted: true,
            browser_authority_session: 1,
            browser_authority_generation: 2,
            policy_generation: 3,
            wallet_session: 4,
            permission_generation: 5,
            navigation_generation: 6,
            wallet_locked: false,
        }
    }

    fn context(nonce: u64) -> RequestContext {
        let binding = binding();
        RequestContext {
            origin: binding.origin,
            namespace: binding.namespace,
            browser_authority_session: binding.browser_authority_session,
            browser_authority_generation: binding.browser_authority_generation,
            policy_generation: binding.policy_generation,
            wallet_session: binding.wallet_session,
            permission_generation: binding.permission_generation,
            navigation_generation: binding.navigation_generation,
            request_nonce: nonce,
            now_unix: 100,
        }
    }

    #[test]
    fn rejects_insecure_cross_origin_stale_and_forbidden_requests() {
        assert!(matches!(
            Origin::parse("http://wallet.example"),
            Err(ProviderError::InsecureContext)
        ));
        let mut provider =
            ProviderCore::new(binding(), MemoryProviderState::default()).expect("core");
        let mut wrong = context(1);
        wrong.origin = Origin::parse("https://other.example").expect("other");
        assert!(matches!(
            provider.request(&wrong, br#"{"method":"wallet_getStatus"}"#),
            Err(ProviderError::StaleContext)
        ));
        assert!(matches!(
            provider.request(
                &context(2),
                br#"{"method":"eth_sendTransaction","params":{}}"#
            ),
            Err(ProviderError::ForbiddenMethod)
        ));
    }

    #[test]
    fn permissions_are_origin_scoped_and_value_movement_always_prompts() {
        let mut provider =
            ProviderCore::new(binding(), MemoryProviderState::default()).expect("core");
        provider
            .state
            .save_permission(&PermissionRecord {
                origin: origin(),
                generation: 5,
                capabilities: BTreeSet::from([PermissionCapability::Send]),
                approved_names: BTreeSet::new(),
                created_at_unix: 1,
                expires_at_unix: None,
            })
            .expect("permission");
        let action = provider
            .request(
                &context(9),
                br#"{"method":"hns_send","params":{"amount":"1","recipient":"hs1q"}}"#,
            )
            .expect("authorized request");
        let ProviderAction::ApprovalRequired(approval) = action else {
            panic!("send must require approval")
        };
        let mut navigated = context(10);
        navigated.navigation_generation += 1;
        assert!(matches!(
            provider.approve(&navigated, approval.id),
            Err(ProviderError::StaleContext) | Err(ProviderError::StaleApproval)
        ));
    }

    #[test]
    fn duplicate_request_nonce_is_rejected() {
        let mut provider =
            ProviderCore::new(binding(), MemoryProviderState::default()).expect("core");
        let bytes = br#"{"method":"wallet_getStatus"}"#;
        provider.request(&context(11), bytes).expect("first");
        assert!(matches!(
            provider.request(&context(11), bytes),
            Err(ProviderError::Replay)
        ));
    }

    #[test]
    fn external_asset_methods_are_generic_and_module_bounded() {
        let mut provider =
            ProviderCore::new(binding(), MemoryProviderState::default()).expect("core");
        assert!(matches!(
            provider.request(
                &context(12),
                br#"{"method":"asset_getBalance","params":{"module":"litecoin"}}"#
            ),
            Err(ProviderError::InvalidParams)
        ));
    }

    #[test]
    fn binding_generations_cannot_regress_within_one_session() {
        let mut provider =
            ProviderCore::new(binding(), MemoryProviderState::default()).expect("core");
        let mut regressed = binding();
        regressed.navigation_generation -= 1;
        assert!(matches!(
            provider.update_binding(regressed),
            Err(ProviderError::StaleContext)
        ));

        let mut replacement_session = binding();
        replacement_session.browser_authority_session = 100;
        replacement_session.wallet_session = 200;
        replacement_session.browser_authority_generation = 1;
        replacement_session.policy_generation = 1;
        replacement_session.permission_generation = 1;
        replacement_session.navigation_generation = 1;
        provider
            .update_binding(replacement_session)
            .expect("random session identities are not ordinal counters");
    }

    #[test]
    fn permission_tombstone_prevents_generation_reset() {
        let mut state = MemoryProviderState::default();
        let record = PermissionRecord {
            origin: origin(),
            generation: 5,
            capabilities: BTreeSet::from([PermissionCapability::Send]),
            approved_names: BTreeSet::new(),
            created_at_unix: 1,
            expires_at_unix: None,
        };
        state.save_permission(&record).expect("trusted bootstrap");
        state
            .revoke_permission(&record.origin, 5, 6, 2)
            .expect("revoke");
        let mut reset = record.clone();
        reset.generation = 6;
        assert!(matches!(
            state.save_permission(&reset),
            Err(ProviderError::StaleContext)
        ));
        reset.generation = 7;
        state
            .save_permission(&reset)
            .expect("next monotonic generation");
    }
}
