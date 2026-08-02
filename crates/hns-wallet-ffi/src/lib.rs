#![doc = "Versioned, typed, secret-minimizing browser wallet ABI."]
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use hns_wallet_types::{
    AccountId, Amount, ApprovalId, ModuleId, PermissionCapability, ReceiveTarget, SyncStatus,
    TransactionSummary, WalletId, WorkflowId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const WALLET_ABI_VERSION: u16 = 1;
pub const MAX_ABI_FRAME_BYTES: usize = 1_048_576;
pub const MAX_PASSPHRASE_BYTES: usize = 1_024;
pub const MAX_RECOVERY_PHRASE_BYTES: usize = 1_024;
pub const MAX_PROVIDER_PARAMS_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    Android,
    Ios,
    ChromiumNativeHost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbiEnvelope<T> {
    pub abi_version: u16,
    pub request_id: u64,
    pub session_nonce: u64,
    pub body: T,
}

impl<T> AbiEnvelope<T> {
    fn validate_header(&self) -> Result<(), AbiError> {
        if self.abi_version != WALLET_ABI_VERSION {
            return Err(AbiError::VersionMismatch);
        }
        if self.request_id == 0 || self.session_nonce == 0 {
            return Err(AbiError::InvalidEnvelope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", content = "parameters", rename_all = "snake_case")]
pub enum WalletRequest {
    Status,
    CreateWallet {
        passphrase: String,
        display_recovery_phrase: bool,
    },
    RestoreWallet {
        passphrase: String,
        recovery_phrase: String,
    },
    Unlock {
        passphrase: String,
    },
    Lock,
    DisplayRecoveryPhrase {
        wallet_id: WalletId,
        dedicated_ui_confirmation_nonce: u64,
    },
    ListAccounts,
    Balance {
        module: ModuleId,
        account: AccountId,
    },
    ReceiveTarget {
        module: ModuleId,
        account: AccountId,
    },
    TransactionHistory {
        module: ModuleId,
        account: AccountId,
    },
    ModuleStatus {
        module: ModuleId,
    },
    ProviderRequest {
        authenticated_origin_context: Vec<u8>,
        method: String,
        params: Value,
    },
    Approve {
        approval_id: ApprovalId,
        authenticated_origin_context: Vec<u8>,
    },
    Reject {
        approval_id: ApprovalId,
    },
    WorkflowStatus {
        workflow_id: WorkflowId,
    },
}

impl WalletRequest {
    fn validate(&self, platform: HostPlatform) -> Result<(), AbiError> {
        match self {
            Self::CreateWallet { passphrase, .. } | Self::Unlock { passphrase } => {
                validate_passphrase(passphrase)
            }
            Self::RestoreWallet {
                passphrase,
                recovery_phrase,
            } => {
                validate_passphrase(passphrase)?;
                if recovery_phrase.is_empty() || recovery_phrase.len() > MAX_RECOVERY_PHRASE_BYTES {
                    return Err(AbiError::InvalidSecretInput);
                }
                Ok(())
            }
            Self::DisplayRecoveryPhrase {
                dedicated_ui_confirmation_nonce,
                ..
            } => {
                if platform == HostPlatform::ChromiumNativeHost {
                    return Err(AbiError::HighRiskOperationUnavailable);
                }
                if *dedicated_ui_confirmation_nonce == 0 {
                    return Err(AbiError::HighRiskConfirmationRequired);
                }
                Ok(())
            }
            Self::ProviderRequest {
                authenticated_origin_context,
                method,
                params,
            } => {
                if authenticated_origin_context.is_empty()
                    || method.is_empty()
                    || method.len() > 128
                    || serde_json::to_vec(params)
                        .map_err(|_| AbiError::InvalidEnvelope)?
                        .len()
                        > MAX_PROVIDER_PARAMS_BYTES
                {
                    return Err(AbiError::InvalidProviderRequest);
                }
                Ok(())
            }
            Self::Approve {
                authenticated_origin_context,
                ..
            } if authenticated_origin_context.is_empty() => Err(AbiError::InvalidProviderRequest),
            _ => Ok(()),
        }
    }
}

fn validate_passphrase(passphrase: &str) -> Result<(), AbiError> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(AbiError::InvalidSecretInput);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
pub enum WalletResponse {
    Status(WalletRuntimeStatus),
    WalletCreated {
        wallet_id: WalletId,
        recovery_phrase_display_required: bool,
    },
    WalletRestored {
        wallet_id: WalletId,
    },
    Locked,
    Unlocked,
    /// This is the sole ABI response permitted to contain a phrase. The
    /// dispatcher refuses it over Chromium native messaging.
    DedicatedRecoveryPhraseDisplay {
        recovery_phrase: String,
    },
    Accounts(Vec<AccountSummary>),
    Balance(Amount),
    ReceiveTarget(ReceiveTarget),
    TransactionHistory(Vec<TransactionSummary>),
    ModuleStatus(SyncStatus),
    Provider(Value),
    ApprovalRequired(ApprovalSummary),
    ApprovalRejected,
    Workflow(WorkflowSummary),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletRuntimeStatus {
    pub locked: bool,
    pub active_wallet: Option<WalletId>,
    pub enabled_modules: BTreeSet<ModuleId>,
    pub mainnet_settlement_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountSummary {
    pub account_id: AccountId,
    pub module: ModuleId,
    pub label: String,
    pub receive_display: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSummary {
    pub approval_id: ApprovalId,
    pub origin: String,
    pub capabilities: BTreeSet<PermissionCapability>,
    pub display_lines: Vec<String>,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkflowSummary {
    pub workflow_id: WorkflowId,
    pub state: String,
    pub next_action: Option<String>,
    pub terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbiFailure {
    pub code: u16,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AbiResult {
    Success(AbiEnvelope<WalletResponse>),
    Failure(AbiEnvelope<AbiFailure>),
}

pub trait WalletRuntime {
    fn handle(
        &mut self,
        platform: HostPlatform,
        request: WalletRequest,
    ) -> Result<WalletResponse, RuntimeError>;
}

/// Parse, validate, and dispatch one complete length-delimited frame. Platform
/// adapters own transport framing; this function never accepts native-host
/// commands, filesystem paths, raw-signing calls, or arbitrary contract calls.
pub fn dispatch_frame<R: WalletRuntime>(
    runtime: &mut R,
    platform: HostPlatform,
    frame: &[u8],
) -> Result<Vec<u8>, AbiError> {
    if frame.is_empty() || frame.len() > MAX_ABI_FRAME_BYTES {
        return Err(AbiError::FrameSize);
    }
    let envelope: AbiEnvelope<WalletRequest> =
        serde_json::from_slice(frame).map_err(|_| AbiError::InvalidEnvelope)?;
    envelope.validate_header()?;
    envelope.body.validate(platform)?;
    let result = runtime.handle(platform, envelope.body);
    let response = match result {
        Ok(body) => {
            if platform == HostPlatform::ChromiumNativeHost
                && matches!(body, WalletResponse::DedicatedRecoveryPhraseDisplay { .. })
            {
                return Err(AbiError::SecretResponseForbidden);
            }
            AbiResult::Success(AbiEnvelope {
                abi_version: WALLET_ABI_VERSION,
                request_id: envelope.request_id,
                session_nonce: envelope.session_nonce,
                body,
            })
        }
        Err(error) => AbiResult::Failure(AbiEnvelope {
            abi_version: WALLET_ABI_VERSION,
            request_id: envelope.request_id,
            session_nonce: envelope.session_nonce,
            body: AbiFailure {
                code: error.code,
                message: error.message,
            },
        }),
    };
    serde_json::to_vec(&response).map_err(|_| AbiError::ResponseEncoding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeError {
    pub code: u16,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AbiError {
    #[error("ABI frame is empty or too large")]
    FrameSize,
    #[error("ABI version mismatch")]
    VersionMismatch,
    #[error("invalid ABI envelope")]
    InvalidEnvelope,
    #[error("secret input is empty or exceeds the bounded maximum")]
    InvalidSecretInput,
    #[error("provider request is invalid or unbounded")]
    InvalidProviderRequest,
    #[error("high-risk recovery operation is unavailable on this transport")]
    HighRiskOperationUnavailable,
    #[error("dedicated high-risk UI confirmation is required")]
    HighRiskConfirmationRequired,
    #[error("a secret-bearing response is forbidden on this transport")]
    SecretResponseForbidden,
    #[error("ABI response encoding failed")]
    ResponseEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Runtime;

    impl WalletRuntime for Runtime {
        fn handle(
            &mut self,
            _platform: HostPlatform,
            request: WalletRequest,
        ) -> Result<WalletResponse, RuntimeError> {
            match request {
                WalletRequest::DisplayRecoveryPhrase { .. } => {
                    Ok(WalletResponse::DedicatedRecoveryPhraseDisplay {
                        recovery_phrase: "test phrase".to_owned(),
                    })
                }
                _ => Ok(WalletResponse::Locked),
            }
        }
    }

    fn frame(body: WalletRequest) -> Vec<u8> {
        serde_json::to_vec(&AbiEnvelope {
            abi_version: WALLET_ABI_VERSION,
            request_id: 1,
            session_nonce: 2,
            body,
        })
        .expect("frame")
    }

    #[test]
    fn rejects_unknown_or_oversized_frames() {
        assert_eq!(
            dispatch_frame(&mut Runtime, HostPlatform::Android, b"{}"),
            Err(AbiError::InvalidEnvelope)
        );
        assert_eq!(
            dispatch_frame(
                &mut Runtime,
                HostPlatform::Android,
                &vec![0; MAX_ABI_FRAME_BYTES + 1]
            ),
            Err(AbiError::FrameSize)
        );
    }

    #[test]
    fn chromium_can_never_receive_a_recovery_phrase() {
        let request = WalletRequest::DisplayRecoveryPhrase {
            wallet_id: WalletId::default(),
            dedicated_ui_confirmation_nonce: 9,
        };
        assert_eq!(
            dispatch_frame(
                &mut Runtime,
                HostPlatform::ChromiumNativeHost,
                &frame(request)
            ),
            Err(AbiError::HighRiskOperationUnavailable)
        );
    }

    #[test]
    fn dedicated_mobile_display_requires_explicit_confirmation() {
        let request = WalletRequest::DisplayRecoveryPhrase {
            wallet_id: WalletId::default(),
            dedicated_ui_confirmation_nonce: 0,
        };
        assert_eq!(
            dispatch_frame(&mut Runtime, HostPlatform::Ios, &frame(request)),
            Err(AbiError::HighRiskConfirmationRequired)
        );
    }
}
