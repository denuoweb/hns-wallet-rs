#![doc = "Release-gated fixed-price Shakedex persistence boundary."]
#![forbid(unsafe_code)]

use hns_swap::SwapProof;
use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{ObjectHash, TransactionHash, WorkflowId, WorkflowKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_LISTING_BYTES: usize = 64 * 1024;
pub const MAX_NAME_BYTES: usize = 63;

/// Canonical Shakedex V2 protocol integration has not been release-qualified.
pub const SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED: bool = false;
/// Denuo V2 publication and discovery have not been release-qualified.
pub const SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED: bool = false;
/// Shakedex transaction construction and value movement have not been release-qualified.
pub const SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SellerState {
    NameSelected,
    TransferPrepared,
    TransferBroadcast,
    TransferLocked,
    FinalizePrepared,
    Locked,
    OfferSigned,
    Published,
    Cancelled,
    Fulfilled,
    RecoveryPrepared,
    RecoveryBroadcast,
    Recovered,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SellerSession {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub state: SellerState,
    pub name: Vec<u8>,
    pub name_hash: ObjectHash,
    pub transfer_txid: Option<TransactionHash>,
    pub finalize_txid: Option<TransactionHash>,
    pub locked_owner_outpoint: Option<Vec<u8>>,
    pub listing_hash: Option<ObjectHash>,
    pub listing_bytes: Option<Vec<u8>>,
    pub fulfillment_txid: Option<TransactionHash>,
    pub recovery_txid: Option<TransactionHash>,
    pub last_verified_height: u64,
    pub failure: Option<String>,
}

impl SellerSession {
    pub fn new(
        workflow_id: WorkflowId,
        name: Vec<u8>,
        name_hash: ObjectHash,
    ) -> Result<Self, ShakedexError> {
        require_release_qualified()?;
        validate_name(&name)?;
        Ok(Self {
            workflow_id,
            revision: 0,
            state: SellerState::NameSelected,
            name,
            name_hash,
            transfer_txid: None,
            finalize_txid: None,
            locked_owner_outpoint: None,
            listing_hash: None,
            listing_bytes: None,
            fulfillment_txid: None,
            recovery_txid: None,
            last_verified_height: 0,
            failure: None,
        })
    }

    pub fn apply<J: ShakedexJournal>(
        &mut self,
        evidence: SellerEvidence,
        journal: &mut J,
    ) -> Result<(), ShakedexError> {
        require_release_qualified()?;
        let mut next = self.clone();
        next.transition(evidence)?;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        journal.save_seller(&next, self.revision)?;
        *self = next;
        Ok(())
    }

    fn transition(&mut self, evidence: SellerEvidence) -> Result<(), ShakedexError> {
        self.state = match (self.state, evidence) {
            (SellerState::NameSelected, SellerEvidence::OwnershipVerified { height }) => {
                self.last_verified_height = height;
                SellerState::TransferPrepared
            }
            (
                SellerState::TransferPrepared,
                SellerEvidence::TransferPersistedAndBroadcast { txid },
            ) => {
                self.transfer_txid = Some(txid);
                SellerState::TransferBroadcast
            }
            (SellerState::TransferBroadcast, SellerEvidence::TransferLockVerified { height }) => {
                self.last_verified_height = height;
                SellerState::TransferLocked
            }
            (SellerState::TransferLocked, SellerEvidence::FinalizePrepared) => {
                SellerState::FinalizePrepared
            }
            (
                SellerState::FinalizePrepared,
                SellerEvidence::LockFinalizeVerified {
                    txid,
                    owner_outpoint,
                    height,
                },
            ) => {
                if owner_outpoint.is_empty() || owner_outpoint.len() > 128 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.finalize_txid = Some(txid);
                self.locked_owner_outpoint = Some(owner_outpoint);
                self.last_verified_height = height;
                SellerState::Locked
            }
            (
                SellerState::Locked,
                SellerEvidence::FixedPriceProofVerified {
                    proof,
                    listing_hash,
                },
            ) => {
                let _ = decode_legacy_swap_proof(&proof)?;
                self.listing_bytes = Some(proof);
                self.listing_hash = Some(listing_hash);
                SellerState::OfferSigned
            }
            (SellerState::OfferSigned, SellerEvidence::DenuoPublicationPersisted) => {
                SellerState::Published
            }
            (SellerState::Published, SellerEvidence::CancellationVerified) => {
                SellerState::Cancelled
            }
            (SellerState::Published, SellerEvidence::FulfillmentVerified { txid, height }) => {
                self.fulfillment_txid = Some(txid);
                self.last_verified_height = height;
                SellerState::Fulfilled
            }
            (
                SellerState::Locked
                | SellerState::OfferSigned
                | SellerState::Published
                | SellerState::Cancelled,
                SellerEvidence::RecoveryPrepared,
            ) => SellerState::RecoveryPrepared,
            (
                SellerState::RecoveryPrepared,
                SellerEvidence::RecoveryPersistedAndBroadcast { txid },
            ) => {
                self.recovery_txid = Some(txid);
                SellerState::RecoveryBroadcast
            }
            (
                SellerState::RecoveryBroadcast,
                SellerEvidence::RecoveryOwnershipVerified { height },
            ) => {
                self.last_verified_height = height;
                SellerState::Recovered
            }
            (state, SellerEvidence::TerminalFailure(reason))
                if !matches!(state, SellerState::Fulfilled | SellerState::Recovered) =>
            {
                if reason.is_empty() || reason.len() > 256 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.failure = Some(reason);
                SellerState::Failed
            }
            _ => return Err(ShakedexError::InvalidTransition),
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SellerEvidence {
    OwnershipVerified {
        height: u64,
    },
    TransferPersistedAndBroadcast {
        txid: TransactionHash,
    },
    TransferLockVerified {
        height: u64,
    },
    FinalizePrepared,
    LockFinalizeVerified {
        txid: TransactionHash,
        owner_outpoint: Vec<u8>,
        height: u64,
    },
    FixedPriceProofVerified {
        proof: Vec<u8>,
        listing_hash: ObjectHash,
    },
    DenuoPublicationPersisted,
    CancellationVerified,
    FulfillmentVerified {
        txid: TransactionHash,
        height: u64,
    },
    RecoveryPrepared,
    RecoveryPersistedAndBroadcast {
        txid: TransactionHash,
    },
    RecoveryOwnershipVerified {
        height: u64,
    },
    TerminalFailure(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyerState {
    Discovered,
    ListingVerified,
    FulfillmentPrepared,
    FulfillmentBroadcast,
    TransferLocked,
    FinalizePrepared,
    FinalizeBroadcast,
    Finalized,
    Conflicted,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BuyerSession {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub state: BuyerState,
    pub listing_hash: ObjectHash,
    pub listing_bytes: Vec<u8>,
    pub fulfillment_txid: Option<TransactionHash>,
    pub finalize_txid: Option<TransactionHash>,
    pub last_verified_height: u64,
    pub failure: Option<String>,
}

impl BuyerSession {
    pub fn discover(
        workflow_id: WorkflowId,
        listing_hash: ObjectHash,
        listing_bytes: Vec<u8>,
    ) -> Result<Self, ShakedexError> {
        require_release_qualified()?;
        let _ = decode_legacy_swap_proof(&listing_bytes)?;
        Ok(Self {
            workflow_id,
            revision: 0,
            state: BuyerState::Discovered,
            listing_hash,
            listing_bytes,
            fulfillment_txid: None,
            finalize_txid: None,
            last_verified_height: 0,
            failure: None,
        })
    }

    pub fn apply<J: ShakedexJournal>(
        &mut self,
        evidence: BuyerEvidence,
        journal: &mut J,
    ) -> Result<(), ShakedexError> {
        require_release_qualified()?;
        let mut next = self.clone();
        next.transition(evidence)?;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        journal.save_buyer(&next, self.revision)?;
        *self = next;
        Ok(())
    }

    fn transition(&mut self, evidence: BuyerEvidence) -> Result<(), ShakedexError> {
        self.state = match (self.state, evidence) {
            (BuyerState::Discovered, BuyerEvidence::CurrentNameAndPresignVerified { height }) => {
                self.last_verified_height = height;
                BuyerState::ListingVerified
            }
            (BuyerState::ListingVerified, BuyerEvidence::FulfillmentPrepared) => {
                BuyerState::FulfillmentPrepared
            }
            (
                BuyerState::FulfillmentPrepared,
                BuyerEvidence::FulfillmentPersistedAndBroadcast { txid },
            ) => {
                self.fulfillment_txid = Some(txid);
                BuyerState::FulfillmentBroadcast
            }
            (
                BuyerState::FulfillmentBroadcast,
                BuyerEvidence::BuyerTransferLockVerified { height },
            ) => {
                self.last_verified_height = height;
                BuyerState::TransferLocked
            }
            (BuyerState::TransferLocked, BuyerEvidence::FinalizePrepared) => {
                BuyerState::FinalizePrepared
            }
            (
                BuyerState::FinalizePrepared,
                BuyerEvidence::FinalizePersistedAndBroadcast { txid },
            ) => {
                self.finalize_txid = Some(txid);
                BuyerState::FinalizeBroadcast
            }
            (BuyerState::FinalizeBroadcast, BuyerEvidence::FinalOwnershipVerified { height }) => {
                self.last_verified_height = height;
                BuyerState::Finalized
            }
            (
                BuyerState::Discovered
                | BuyerState::ListingVerified
                | BuyerState::FulfillmentPrepared
                | BuyerState::FulfillmentBroadcast,
                BuyerEvidence::ConflictingFulfillmentVerified,
            ) => BuyerState::Conflicted,
            (state, BuyerEvidence::TerminalFailure(reason)) if state != BuyerState::Finalized => {
                if reason.is_empty() || reason.len() > 256 {
                    return Err(ShakedexError::InvalidEvidence);
                }
                self.failure = Some(reason);
                BuyerState::Failed
            }
            _ => return Err(ShakedexError::InvalidTransition),
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuyerEvidence {
    CurrentNameAndPresignVerified { height: u64 },
    FulfillmentPrepared,
    FulfillmentPersistedAndBroadcast { txid: TransactionHash },
    BuyerTransferLockVerified { height: u64 },
    FinalizePrepared,
    FinalizePersistedAndBroadcast { txid: TransactionHash },
    FinalOwnershipVerified { height: u64 },
    ConflictingFulfillmentVerified,
    TerminalFailure(String),
}

pub trait ShakedexJournal {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError>;
    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError>;
}

pub struct WalletShakedexJournal<'a> {
    pub store: &'a mut WalletStore,
    pub updated_at_unix: u64,
}

impl ShakedexJournal for WalletShakedexJournal<'_> {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        let revision = self.store.save_workflow(
            session.workflow_id,
            WorkflowKind::ShakedexSeller,
            expected_revision,
            session,
            matches!(
                session.state,
                SellerState::TransferPrepared
                    | SellerState::FinalizePrepared
                    | SellerState::RecoveryPrepared
            ),
            self.updated_at_unix,
        )?;
        if revision != session.revision {
            return Err(ShakedexError::Invariant);
        }
        Ok(())
    }

    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        let revision = self.store.save_workflow(
            session.workflow_id,
            WorkflowKind::ShakedexBuyer,
            expected_revision,
            session,
            matches!(
                session.state,
                BuyerState::FulfillmentPrepared | BuyerState::FinalizePrepared
            ),
            self.updated_at_unix,
        )?;
        if revision != session.revision {
            return Err(ShakedexError::Invariant);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryJournal {
    pub seller: Vec<SellerSession>,
    pub buyer: Vec<BuyerSession>,
}

impl ShakedexJournal for MemoryJournal {
    fn save_seller(
        &mut self,
        session: &SellerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        if session.revision != expected_revision + 1 {
            return Err(ShakedexError::StaleRevision);
        }
        self.seller.push(session.clone());
        Ok(())
    }

    fn save_buyer(
        &mut self,
        session: &BuyerSession,
        expected_revision: u64,
    ) -> Result<(), ShakedexError> {
        if session.revision != expected_revision + 1 {
            return Err(ShakedexError::StaleRevision);
        }
        self.buyer.push(session.clone());
        Ok(())
    }
}

fn validate_name(name: &[u8]) -> Result<(), ShakedexError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || !name.is_ascii() {
        return Err(ShakedexError::InvalidName);
    }
    Ok(())
}

fn require_release_qualified() -> Result<(), ShakedexError> {
    if !SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED {
        return Err(ShakedexError::CanonicalProtocolUnavailable);
    }
    if !SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED {
        return Err(ShakedexError::DenuoProtocolUnavailable);
    }
    if !SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED {
        return Err(ShakedexError::ValueRuntimeUnavailable);
    }
    Ok(())
}

/// Decodes the released v0.1 proof envelope for legacy persisted-state
/// inspection only. Structural decoding does not verify signatures, network,
/// current ownership, locking coins, or canonical V2 listing identity and must
/// never authorize a workflow transition.
fn decode_legacy_swap_proof(bytes: &[u8]) -> Result<SwapProof, ShakedexError> {
    if bytes.is_empty() || bytes.len() > MAX_LISTING_BYTES {
        return Err(ShakedexError::InvalidListing);
    }
    SwapProof::decode(bytes).map_err(|_| ShakedexError::InvalidListing)
}

#[derive(Debug, Error)]
pub enum ShakedexError {
    #[error("canonical Shakedex V2 protocol is not release-qualified")]
    CanonicalProtocolUnavailable,
    #[error("Denuo V2 publication and discovery are not release-qualified")]
    DenuoProtocolUnavailable,
    #[error("Shakedex value runtime is not release-qualified")]
    ValueRuntimeUnavailable,
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("invalid or oversized Shakedex proof")]
    InvalidListing,
    #[error("verified evidence does not permit this transition")]
    InvalidTransition,
    #[error("name or transaction evidence is invalid")]
    InvalidEvidence,
    #[error("persisted state invariant failed")]
    Invariant,
    #[error("persisted workflow revision is stale")]
    StaleRevision,
    #[error("wallet persistence failed")]
    Persistence,
}

impl From<StoreError> for ShakedexError {
    fn from(_: StoreError) -> Self {
        Self::Persistence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seller_entrypoints_fail_closed_for_new_and_restored_sessions() {
        assert!(!SHAKEDEX_CANONICAL_V2_RELEASE_QUALIFIED);
        assert!(!SHAKEDEX_DENUO_V2_RELEASE_QUALIFIED);
        assert!(!SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED);
        assert!(matches!(
            SellerSession::new(
                WorkflowId::new([1; 16]),
                b"example".to_vec(),
                ObjectHash::new([2; 32]),
            ),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));

        // Existing persisted records can deserialize directly into this public
        // schema, so apply must enforce the gate independently of creation.
        let mut session = SellerSession {
            workflow_id: WorkflowId::new([1; 16]),
            revision: 7,
            state: SellerState::Cancelled,
            name: b"example".to_vec(),
            name_hash: ObjectHash::new([2; 32]),
            transfer_txid: None,
            finalize_txid: None,
            locked_owner_outpoint: None,
            listing_hash: None,
            listing_bytes: None,
            fulfillment_txid: None,
            recovery_txid: None,
            last_verified_height: 0,
            failure: None,
        };
        let original = session.clone();
        let mut journal = MemoryJournal::default();
        assert!(matches!(
            session.apply(SellerEvidence::RecoveryPrepared, &mut journal),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));
        assert_eq!(session, original);
        assert!(journal.seller.is_empty());
    }

    #[test]
    fn buyer_entrypoints_fail_closed_for_discovery_and_restored_sessions() {
        assert!(matches!(
            BuyerSession::discover(
                WorkflowId::new([3; 16]),
                ObjectHash::new([4; 32]),
                vec![1],
            ),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));

        // A deserialized pre-gate session must not bypass the apply boundary.
        let mut buyer = BuyerSession {
            workflow_id: WorkflowId::new([3; 16]),
            revision: 9,
            state: BuyerState::ListingVerified,
            listing_hash: ObjectHash::new([4; 32]),
            listing_bytes: vec![1],
            fulfillment_txid: None,
            finalize_txid: None,
            last_verified_height: 0,
            failure: None,
        };
        let original = buyer.clone();
        let mut journal = MemoryJournal::default();
        assert!(matches!(
            buyer.apply(BuyerEvidence::FulfillmentPrepared, &mut journal),
            Err(ShakedexError::CanonicalProtocolUnavailable)
        ));
        assert_eq!(buyer, original);
        assert!(journal.buyer.is_empty());
    }
}
