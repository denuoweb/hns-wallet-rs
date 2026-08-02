#![doc = "Crash-recoverable fixed-price Shakedex orchestration."]
#![forbid(unsafe_code)]

use hns_swap::SwapProof;
use hns_wallet_store::{StoreError, WalletStore};
use hns_wallet_types::{ObjectHash, TransactionHash, WorkflowId, WorkflowKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_LISTING_BYTES: usize = 64 * 1024;
pub const MAX_NAME_BYTES: usize = 63;

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
                verify_swap_proof(&proof)?;
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
        verify_swap_proof(&listing_bytes)?;
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

fn verify_swap_proof(bytes: &[u8]) -> Result<(), ShakedexError> {
    if bytes.is_empty() || bytes.len() > MAX_LISTING_BYTES {
        return Err(ShakedexError::InvalidListing);
    }
    SwapProof::decode(bytes).map_err(|_| ShakedexError::InvalidListing)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum ShakedexError {
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
    fn seller_recovery_is_available_from_locked_and_cancelled_states() {
        let mut session = SellerSession::new(
            WorkflowId::new([1; 16]),
            b"example".to_vec(),
            ObjectHash::new([2; 32]),
        )
        .expect("seller");
        session.state = SellerState::Cancelled;
        let mut journal = MemoryJournal::default();
        session
            .apply(SellerEvidence::RecoveryPrepared, &mut journal)
            .expect("prepare recovery");
        session
            .apply(
                SellerEvidence::RecoveryPersistedAndBroadcast {
                    txid: TransactionHash::new([3; 32]),
                },
                &mut journal,
            )
            .expect("broadcast recovery");
        session
            .apply(
                SellerEvidence::RecoveryOwnershipVerified { height: 10 },
                &mut journal,
            )
            .expect("verify recovery");
        assert_eq!(session.state, SellerState::Recovered);
        assert_eq!(journal.seller.last(), Some(&session));
    }

    #[test]
    fn buyer_cannot_finalize_before_verified_transfer_lock() {
        // This test constructs the state after canonical proof verification;
        // proof codec vectors live in hns-swap.
        let mut buyer = BuyerSession {
            workflow_id: WorkflowId::new([4; 16]),
            revision: 0,
            state: BuyerState::ListingVerified,
            listing_hash: ObjectHash::new([5; 32]),
            listing_bytes: vec![1],
            fulfillment_txid: None,
            finalize_txid: None,
            last_verified_height: 0,
            failure: None,
        };
        assert!(matches!(
            buyer.apply(
                BuyerEvidence::FinalizePrepared,
                &mut MemoryJournal::default()
            ),
            Err(ShakedexError::InvalidTransition)
        ));
    }
}
