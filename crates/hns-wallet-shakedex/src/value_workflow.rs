use hns_transaction::{Address, Coin, Transaction};
use hns_wallet_hns::{
    DEFAULT_FEE_TARGET_BLOCKS, HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED,
    HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED, HNS_VALUE_RUNTIME_RELEASE_QUALIFIED, HnsBackend,
    HnsClock, HnsInputReservation, HnsShakedexFundingApprovalExpectation,
    HnsShakedexFundingPurpose, HnsShakedexFundingReservation, HnsShakedexFundingReservationState,
    HnsShakedexFundingScope, HnsTransactionFeeQuote, HnsWalletRuntime, MempoolSnapshotBinding,
    OutpointSpendEvidence, PREPARED_ARTIFACT_LIFETIME_SECONDS, SnapshotBinding,
    TransactionEvidence, TransactionInclusion, VerifiedCurrentShakedexLock,
    activate_hns_shakedex_funding_reservations, create_hns_shakedex_funding_reservations,
    delete_hns_shakedex_funding_reservations, retain_active_hns_shakedex_funding_reservations,
    validate_hns_shakedex_final_fee_quote_evidence, validate_hns_shakedex_funding_reservations,
    validate_persisted_hns_shakedex_fee_quote_evidence,
};
use hns_wallet_store::{EntityKind, StoredWorkflow, WalletStore};
use hns_wallet_types::{
    ApprovalId, BaseUnits, ObjectHash, TransactionHash, WorkflowId, WorkflowKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plans::{AddressEvidence, CoinEvidence};
use crate::transactions::{verify_prepared_buyer_funding, verify_prepared_seller_recovery_funding};
use crate::{
    BuyerLockPlan, BuyerLockPlanState, PreparedBuyerFulfillment,
    SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED, SellerAuthorizedRecovery, SellerLockPlan,
    SellerLockPlanState, ShakedexError, SuppliedShakedexLock, verify_signed_buyer_fulfillment,
    verify_signed_seller_recovery,
};

const SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION: u16 = 1;
pub const MAX_SHAKEDEX_VALUE_WORKFLOWS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakedexValueAction {
    BuyerFulfillment,
    SellerRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShakedexValueStage {
    Prepared,
    Authorized,
    RequiresRebroadcast,
    Broadcast,
    Mempool,
    Confirming,
    Confirmed,
    Conflicted,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum StructuralPlan {
    Buyer { plan: BuyerLockPlan },
    Seller { plan: SellerLockPlan },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedTransaction {
    approval_id: ApprovalId,
    transaction: TransactionHash,
    transaction_bytes: Vec<u8>,
    fee_quote: HnsTransactionFeeQuote,
    authorized_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexChainObservation {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub inclusion: Option<TransactionInclusion>,
    pub in_mempool: bool,
    pub confirmation_count: u32,
    pub conflicted: bool,
    pub observed_at_unix: u64,
}

/// One aggregate funds-safety record for a post-lock Shakedex value action.
/// The canonical structural plan, exact primary/funding coins, prepared bytes,
/// approval, final fee quote, signed bytes, submission fence, and chain
/// observation advance under one encrypted workflow CAS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShakedexValueWorkflow {
    schema_version: u16,
    workflow_id: WorkflowId,
    action: ShakedexValueAction,
    structural_plan: StructuralPlan,
    structural_plan_commitment: ObjectHash,
    funding_reservation: HnsShakedexFundingReservation,
    source_coin: CoinEvidence,
    funding_input_coins: Vec<CoinEvidence>,
    recipient: AddressEvidence,
    value_base_units: BaseUnits,
    fee_base_units: BaseUnits,
    maximum_fee: BaseUnits,
    minimum_confirmations: u32,
    prepared_transaction: Vec<u8>,
    expires_at_unix: u64,
    stage: ShakedexValueStage,
    authorized: Option<AuthorizedTransaction>,
    submission_attempts: u32,
    submission_started_at_unix: Option<u64>,
    accepted_at_unix: Option<u64>,
    last_chain_observation: Option<ShakedexChainObservation>,
    confirmed_once: bool,
    conflicted_once: bool,
    competing_spenders: Vec<TransactionHash>,
}

impl ShakedexValueWorkflow {
    #[allow(clippy::too_many_arguments)]
    pub fn prepared_buyer_fulfillment(
        plan: BuyerLockPlan,
        prepared: &PreparedBuyerFulfillment,
        funding_reservation: HnsShakedexFundingReservation,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if plan.state() != BuyerLockPlanState::OfferVerified
            || plan.supplied_lock()?.descriptor() != prepared.supplied_lock().descriptor()
            || plan.supplied_lock()?.locking_coin() != prepared.supplied_lock().locking_coin()
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let listing = plan.authenticated_listing()?;
        verify_prepared_buyer_funding(
            &listing,
            prepared.supplied_lock(),
            prepared.expected_recipient(),
            prepared.buyer_input_coins(),
            prepared.fee_base_units(),
            prepared.transaction_bytes(),
        )?;
        let value_base_units = BaseUnits::new(u128::from(listing.price_base_units()));
        Self::prepared(
            ShakedexValueAction::BuyerFulfillment,
            StructuralPlan::Buyer { plan },
            funding_reservation,
            prepared.supplied_lock().locking_coin(),
            prepared.buyer_input_coins(),
            prepared.expected_recipient(),
            value_base_units,
            prepared.fee_base_units(),
            maximum_fee,
            minimum_confirmations,
            prepared.transaction_bytes(),
            expires_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepared_seller_recovery(
        plan: SellerLockPlan,
        prepared: &SellerAuthorizedRecovery,
        funding_reservation: HnsShakedexFundingReservation,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if plan.state() != SellerLockPlanState::Locked
            || plan.supplied_lock()?.descriptor() != prepared.supplied_lock().descriptor()
            || plan.supplied_lock()?.locking_coin() != prepared.supplied_lock().locking_coin()
        {
            return Err(ShakedexError::InvalidTransition);
        }
        verify_prepared_seller_recovery_funding(
            prepared.supplied_lock(),
            prepared.recovery_recipient(),
            prepared.funding_input_coins(),
            prepared.fee_base_units(),
            prepared.transaction_bytes(),
        )?;
        let value_base_units = BaseUnits::new(u128::from(
            prepared.supplied_lock().locking_coin().value.get(),
        ));
        Self::prepared(
            ShakedexValueAction::SellerRecovery,
            StructuralPlan::Seller { plan },
            funding_reservation,
            prepared.supplied_lock().locking_coin(),
            prepared.funding_input_coins(),
            prepared.recovery_recipient(),
            value_base_units,
            prepared.fee_base_units(),
            maximum_fee,
            minimum_confirmations,
            prepared.transaction_bytes(),
            expires_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepared(
        action: ShakedexValueAction,
        structural_plan: StructuralPlan,
        funding_reservation: HnsShakedexFundingReservation,
        source_coin: &Coin,
        funding_input_coins: &[Coin],
        recipient: &Address,
        value_base_units: BaseUnits,
        fee_base_units: u64,
        maximum_fee: BaseUnits,
        minimum_confirmations: u32,
        prepared_transaction: &[u8],
        expires_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        let parent_workflow_id = match &structural_plan {
            StructuralPlan::Buyer { plan } => plan.workflow_id(),
            StructuralPlan::Seller { plan } => plan.workflow_id(),
        };
        let workflow_id = shakedex_value_workflow_id(parent_workflow_id, action);
        let structural_plan_commitment = structural_plan_commitment(&structural_plan)?;
        let workflow = Self {
            schema_version: SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION,
            workflow_id,
            action,
            structural_plan,
            structural_plan_commitment,
            funding_reservation,
            source_coin: CoinEvidence::from_coin(source_coin)?,
            funding_input_coins: funding_input_coins
                .iter()
                .map(CoinEvidence::from_coin)
                .collect::<Result<_, _>>()?,
            recipient: AddressEvidence::from_address(recipient)?,
            value_base_units,
            fee_base_units: BaseUnits::new(u128::from(fee_base_units)),
            maximum_fee,
            minimum_confirmations,
            prepared_transaction: prepared_transaction.to_vec(),
            expires_at_unix,
            stage: ShakedexValueStage::Prepared,
            authorized: None,
            submission_attempts: 0,
            submission_started_at_unix: None,
            accepted_at_unix: None,
            last_chain_observation: None,
            confirmed_once: false,
            conflicted_once: false,
            competing_spenders: Vec::new(),
        };
        workflow.validate()?;
        Ok(workflow)
    }

    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub const fn parent_workflow_id(&self) -> WorkflowId {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.workflow_id(),
            StructuralPlan::Seller { plan } => plan.workflow_id(),
        }
    }

    pub const fn action(&self) -> ShakedexValueAction {
        self.action
    }

    pub const fn stage(&self) -> ShakedexValueStage {
        self.stage
    }

    pub const fn value_base_units(&self) -> BaseUnits {
        self.value_base_units
    }

    pub const fn fee_base_units(&self) -> BaseUnits {
        self.fee_base_units
    }

    pub const fn maximum_fee(&self) -> BaseUnits {
        self.maximum_fee
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }

    pub fn prepared_transaction(&self) -> &[u8] {
        &self.prepared_transaction
    }

    pub fn signed_transaction(&self) -> Option<&[u8]> {
        self.authorized
            .as_ref()
            .map(|authorized| authorized.transaction_bytes.as_slice())
    }

    pub fn transaction(&self) -> Option<TransactionHash> {
        self.authorized
            .as_ref()
            .map(|authorized| authorized.transaction)
    }

    pub fn fee_quote(&self) -> Option<&HnsTransactionFeeQuote> {
        self.authorized
            .as_ref()
            .map(|authorized| &authorized.fee_quote)
    }

    pub const fn last_chain_observation(&self) -> Option<&ShakedexChainObservation> {
        self.last_chain_observation.as_ref()
    }

    pub fn competing_spenders(&self) -> &[TransactionHash] {
        &self.competing_spenders
    }

    pub(crate) fn source_coin(&self) -> Result<Coin, ShakedexError> {
        self.source_coin.to_coin()
    }

    pub const fn funding_reservation(&self) -> &HnsShakedexFundingReservation {
        &self.funding_reservation
    }

    pub(crate) fn funding_input_coins(&self) -> Result<Vec<Coin>, ShakedexError> {
        self.funding_input_coins
            .iter()
            .map(CoinEvidence::to_coin)
            .collect()
    }

    fn all_input_coins(&self) -> Result<Vec<Coin>, ShakedexError> {
        let mut coins = Vec::with_capacity(self.funding_input_coins.len() + 1);
        coins.push(self.source_coin()?);
        coins.extend(self.funding_input_coins()?);
        Ok(coins)
    }

    pub fn recipient(&self) -> Result<Address, ShakedexError> {
        self.recipient.to_address()
    }

    pub(crate) fn wallet_and_account(
        &self,
    ) -> (hns_wallet_types::WalletId, hns_wallet_types::AccountId) {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => (plan.wallet_id(), plan.account_id()),
            StructuralPlan::Seller { plan } => (plan.wallet_id(), plan.account_id()),
        }
    }

    pub(crate) fn name_hash(&self) -> ObjectHash {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.name_hash(),
            StructuralPlan::Seller { plan } => plan.name_hash(),
        }
    }

    pub(crate) fn supplied_lock(&self) -> Result<SuppliedShakedexLock, ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => plan.supplied_lock(),
            StructuralPlan::Seller { plan } => plan.supplied_lock(),
        }
    }

    pub(crate) fn approval_commitment(&self, revision: u64) -> Result<Vec<u8>, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared || self.authorized.is_some() {
            return Err(ShakedexError::InvalidTransition);
        }
        serde_json::to_vec(&ShakedexValueApprovalCommitment {
            domain: "hns-wallet-rs/shakedex-value-approval/v1",
            revision,
            workflow: self,
        })
        .map_err(|_| ShakedexError::Encoding)
    }

    pub(crate) fn authorize(
        &self,
        approval_id: ApprovalId,
        signed_transaction: Vec<u8>,
        fee_quote: HnsTransactionFeeQuote,
        authorized_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared
            || self.authorized.is_some()
            || authorized_at_unix >= self.expires_at_unix
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let transaction = self.verify_signed(&signed_transaction)?;
        if fee_quote.txid != transaction || fee_quote.actual_fee != self.fee_base_units {
            return Err(ShakedexError::InvalidFeeEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::Authorized;
        next.authorized = Some(AuthorizedTransaction {
            approval_id,
            transaction,
            transaction_bytes: signed_transaction,
            fee_quote,
            authorized_at_unix,
        });
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn begin_submission(
        &self,
        refreshed_quote: HnsTransactionFeeQuote,
        started_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if !matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
        ) {
            return Err(ShakedexError::InvalidTransition);
        }
        let authorized = self
            .authorized
            .as_ref()
            .ok_or(ShakedexError::InvalidTransition)?;
        if refreshed_quote.txid != authorized.transaction
            || refreshed_quote.actual_fee != self.fee_base_units
            || !snapshot_binding_not_older(refreshed_quote.binding, authorized.fee_quote.binding)
            || !mempool_binding_not_older(refreshed_quote.mempool, authorized.fee_quote.mempool)
            || started_at_unix < authorized.authorized_at_unix
            || self
                .last_chain_observation
                .as_ref()
                .is_some_and(|observation| {
                    !submission_evidence_not_older(
                        refreshed_quote.binding,
                        refreshed_quote.mempool,
                        started_at_unix,
                        observation,
                    )
                })
        {
            return Err(ShakedexError::InvalidFeeEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::RequiresRebroadcast;
        next.submission_attempts = next
            .submission_attempts
            .checked_add(1)
            .ok_or(ShakedexError::Invariant)?;
        next.submission_started_at_unix = Some(started_at_unix);
        next.accepted_at_unix = None;
        next.last_chain_observation = None;
        next.competing_spenders.clear();
        next.authorized
            .as_mut()
            .ok_or(ShakedexError::Invariant)?
            .fee_quote = refreshed_quote;
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn record_broadcast(
        &self,
        returned_transaction: TransactionHash,
        accepted_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        let expected = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        if self.stage != ShakedexValueStage::RequiresRebroadcast
            || returned_transaction != expected
            || self.submission_started_at_unix.is_none()
            || self
                .submission_started_at_unix
                .is_some_and(|started| accepted_at_unix < started)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let mut next = self.clone();
        next.stage = ShakedexValueStage::Broadcast;
        next.accepted_at_unix = Some(accepted_at_unix);
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn reconcile(
        &self,
        transaction_evidence: &TransactionEvidence,
        spend_evidence: &OutpointSpendEvidence,
        observed_at_unix: u64,
    ) -> Result<Self, ShakedexError> {
        if !matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
        ) {
            return Err(ShakedexError::InvalidTransition);
        }
        let transaction = self.transaction().ok_or(ShakedexError::InvalidTransition)?;
        validate_transaction_evidence(self, transaction_evidence)?;
        let competing_spenders =
            validate_spend_evidence(self, spend_evidence, transaction, transaction_evidence)?;
        let status = transaction_evidence.status;
        let next_stage = if status.conflicted || !competing_spenders.is_empty() {
            ShakedexValueStage::Conflicted
        } else if status.confirmation_count >= self.minimum_confirmations {
            ShakedexValueStage::Confirmed
        } else if status.confirmation_count > 0 {
            ShakedexValueStage::Confirming
        } else if status.in_mempool {
            ShakedexValueStage::Mempool
        } else if matches!(
            self.stage,
            ShakedexValueStage::Authorized
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
                | ShakedexValueStage::RequiresRebroadcast
        ) {
            ShakedexValueStage::RequiresRebroadcast
        } else {
            self.stage
        };
        let mut next = self.clone();
        next.stage = next_stage;
        next.confirmed_once |= next_stage == ShakedexValueStage::Confirmed;
        next.conflicted_once |= next_stage == ShakedexValueStage::Conflicted;
        next.competing_spenders = competing_spenders;
        next.last_chain_observation = Some(ShakedexChainObservation {
            binding: transaction_evidence.binding,
            mempool: transaction_evidence.mempool,
            inclusion: transaction_evidence.inclusion,
            in_mempool: status.in_mempool,
            confirmation_count: status.confirmation_count,
            conflicted: status.conflicted,
            observed_at_unix,
        });
        next.validate()?;
        Ok(next)
    }

    pub fn validate_current_lock(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
    ) -> Result<(), ShakedexError> {
        let supplied = self.supplied_lock()?;
        if current_lock.descriptor() != supplied.descriptor()
            || current_lock.locking_coin() != supplied.locking_coin()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        if self.schema_version != SHAKEDEX_VALUE_WORKFLOW_SCHEMA_VERSION
            || self.workflow_id.as_bytes() == &[0; 16]
            || self.structural_plan_commitment != structural_plan_commitment(&self.structural_plan)?
            || self.value_base_units.is_zero()
            || self.fee_base_units.is_zero()
            || self.maximum_fee < self.fee_base_units
            || self.minimum_confirmations == 0
            || self.expires_at_unix == 0
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let (plan_workflow_id, plan_action, plan_source, expected_value) =
            self.validate_structural_plan()?;
        if let StructuralPlan::Buyer { plan } = &self.structural_plan {
            if self.expires_at_unix > plan.authenticated_listing()?.expires_at_unix() {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
        let (wallet_id, account_id) = self.wallet_and_account();
        let expected_purpose = match self.action {
            ShakedexValueAction::BuyerFulfillment => HnsShakedexFundingPurpose::BuyerFulfillment,
            ShakedexValueAction::SellerRecovery => HnsShakedexFundingPurpose::SellerRecovery,
        };
        let source_outpoint = hns_wallet_hns::HnsOutpoint {
            transaction: TransactionHash::new(plan_source.outpoint.transaction_hash.into_bytes()),
            output_index: plan_source.outpoint.index,
        };
        if shakedex_value_workflow_id(plan_workflow_id, plan_action) != self.workflow_id
            || plan_action != self.action
            || self.source_coin.to_coin()? != plan_source
            || self.value_base_units != expected_value
            || self.funding_reservation.wallet_id() != wallet_id
            || self.funding_reservation.account_id() != account_id
            || self.funding_reservation.workflow_id() != self.workflow_id
            || self.funding_reservation.purpose() != expected_purpose
            || self.funding_reservation.name_hash() != self.name_hash().into_bytes()
            || self.funding_reservation.source_outpoint() != source_outpoint
            || self.funding_reservation.expires_at_unix() != self.expires_at_unix
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let prepared = canonical_transaction(&self.prepared_transaction)?;
        let funding = self.funding_input_coins()?;
        if funding.is_empty()
            || funding.len() > crate::MAX_SHAKEDEX_FUNDING_INPUTS
            || prepared.inputs.len() != funding.len() + 1
            || self.competing_spenders.len() > prepared.inputs.len()
            || self
                .competing_spenders
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self.funding_reservation.funding_inputs().len() != funding.len()
            || self
                .funding_reservation
                .funding_inputs()
                .iter()
                .zip(&funding)
                .any(|(tracked, canonical)| {
                    !matches!(tracked.to_canonical_coin(), Ok(coin) if coin == *canonical)
                })
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.verify_prepared()?;
        match (self.stage, self.authorized.as_ref()) {
            (
                ShakedexValueStage::Prepared
                | ShakedexValueStage::Expired
                | ShakedexValueStage::Cancelled,
                None,
            ) => {
                if self.submission_attempts != 0
                    || self.submission_started_at_unix.is_some()
                    || self.accepted_at_unix.is_some()
                    || self.last_chain_observation.is_some()
                    || self.confirmed_once
                    || self.conflicted_once
                    || !self.competing_spenders.is_empty()
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
            (
                ShakedexValueStage::Authorized
                | ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted,
                Some(authorized),
            ) => {
                if self.verify_signed(&authorized.transaction_bytes)? != authorized.transaction
                    || authorized.fee_quote.txid != authorized.transaction
                    || authorized.fee_quote.actual_fee != self.fee_base_units
                {
                    return Err(ShakedexError::InvalidFeeEvidence);
                }
                validate_persisted_hns_shakedex_fee_quote_evidence(
                    &plan_source,
                    &funding,
                    &authorized.transaction_bytes,
                    &authorized.fee_quote,
                    self.fee_base_units,
                    self.maximum_fee,
                )?;
            }
            _ => return Err(ShakedexError::InvalidEvidence),
        }
        if self.stage == ShakedexValueStage::Authorized
            && (self.submission_attempts != 0
                || self.submission_started_at_unix.is_some()
                || self.accepted_at_unix.is_some()
                || self.last_chain_observation.is_some()
                || self.confirmed_once
                || self.conflicted_once
                || !self.competing_spenders.is_empty())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let post_authorization_stage = matches!(
            self.stage,
            ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Broadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted
        );
        if post_authorization_stage
            && ((self.submission_attempts == 0) != self.submission_started_at_unix.is_none()
                || self.submission_attempts == 0 && self.last_chain_observation.is_none())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        if self.accepted_at_unix.is_some_and(|accepted| {
            self.submission_attempts == 0
                || self
                    .submission_started_at_unix
                    .is_none_or(|started| accepted < started)
        }) {
            return Err(ShakedexError::InvalidEvidence);
        }
        if self.stage == ShakedexValueStage::Broadcast
            && (self.submission_attempts == 0 || self.accepted_at_unix.is_none())
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.validate_chain_observation()?;
        Ok(())
    }

    fn validate_chain_observation(&self) -> Result<(), ShakedexError> {
        let Some(observation) = self.last_chain_observation.as_ref() else {
            if matches!(
                self.stage,
                ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted
            ) {
                return Err(ShakedexError::InvalidEvidence);
            }
            return Ok(());
        };
        if self.authorized.as_ref().is_none_or(|authorized| {
            observation.observed_at_unix < authorized.authorized_at_unix
                || !snapshot_binding_not_older(observation.binding, authorized.fee_quote.binding)
                || !mempool_binding_not_older(observation.mempool, authorized.fee_quote.mempool)
        }) {
            return Err(ShakedexError::InvalidEvidence);
        }
        let confirmation_count_matches = match observation.inclusion {
            Some(inclusion) => {
                inclusion.height <= observation.binding.tip.height
                    && observation.confirmation_count
                        == u32::try_from(
                            observation
                                .binding
                                .tip
                                .height
                                .checked_sub(inclusion.height)
                                .and_then(|depth| depth.checked_add(1))
                                .ok_or(ShakedexError::InvalidEvidence)?,
                        )
                        .map_err(|_| ShakedexError::InvalidEvidence)?
            }
            None => observation.confirmation_count == 0,
        };
        if observation.observed_at_unix == 0
            || !confirmation_count_matches
            || observation.confirmation_count > 0 && observation.inclusion.is_none()
            || observation.confirmation_count == 0 && observation.inclusion.is_some()
            || observation.conflicted
                && (observation.in_mempool || observation.confirmation_count > 0)
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        let valid_for_stage = match self.stage {
            ShakedexValueStage::RequiresRebroadcast => {
                !observation.in_mempool
                    && observation.confirmation_count == 0
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Mempool => {
                observation.in_mempool
                    && observation.confirmation_count == 0
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Confirming => {
                !observation.in_mempool
                    && observation.confirmation_count > 0
                    && observation.confirmation_count < self.minimum_confirmations
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
            }
            ShakedexValueStage::Confirmed => {
                !observation.in_mempool
                    && observation.confirmation_count >= self.minimum_confirmations
                    && !observation.conflicted
                    && self.competing_spenders.is_empty()
                    && self.confirmed_once
            }
            ShakedexValueStage::Conflicted => {
                self.conflicted_once
                    && (observation.conflicted || !self.competing_spenders.is_empty())
            }
            ShakedexValueStage::Prepared
            | ShakedexValueStage::Authorized
            | ShakedexValueStage::Broadcast
            | ShakedexValueStage::Expired
            | ShakedexValueStage::Cancelled => false,
        };
        if !valid_for_stage {
            return Err(ShakedexError::InvalidEvidence);
        }
        Ok(())
    }

    fn validate_structural_plan(
        &self,
    ) -> Result<(WorkflowId, ShakedexValueAction, Coin, BaseUnits), ShakedexError> {
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => {
                plan.validate()?;
                if plan.state() != BuyerLockPlanState::OfferVerified {
                    return Err(ShakedexError::InvalidTransition);
                }
                Ok((
                    plan.workflow_id(),
                    ShakedexValueAction::BuyerFulfillment,
                    plan.locking_coin()?,
                    BaseUnits::new(u128::from(plan.authenticated_listing()?.price_base_units())),
                ))
            }
            StructuralPlan::Seller { plan } => {
                plan.validate()?;
                if plan.state() != SellerLockPlanState::Locked {
                    return Err(ShakedexError::InvalidTransition);
                }
                let source = plan.locking_coin()?;
                Ok((
                    plan.workflow_id(),
                    ShakedexValueAction::SellerRecovery,
                    source.clone(),
                    BaseUnits::new(u128::from(source.value.get())),
                ))
            }
        }
    }

    fn verify_prepared(&self) -> Result<(), ShakedexError> {
        let recipient = self.recipient()?;
        let funding = self.funding_input_coins()?;
        let fee =
            u64::try_from(self.fee_base_units.get()).map_err(|_| ShakedexError::InvalidEvidence)?;
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => verify_prepared_buyer_funding(
                &plan.authenticated_listing()?,
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                &self.prepared_transaction,
            ),
            StructuralPlan::Seller { plan } => verify_prepared_seller_recovery_funding(
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                &self.prepared_transaction,
            ),
        }
    }

    fn verify_signed(&self, signed: &[u8]) -> Result<TransactionHash, ShakedexError> {
        require_only_funding_witness_changes(&self.prepared_transaction, signed)?;
        let recipient = self.recipient()?;
        let funding = self.funding_input_coins()?;
        let fee =
            u64::try_from(self.fee_base_units.get()).map_err(|_| ShakedexError::InvalidEvidence)?;
        match &self.structural_plan {
            StructuralPlan::Buyer { plan } => verify_signed_buyer_fulfillment(
                &plan.authenticated_listing()?,
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction()),
            StructuralPlan::Seller { plan } => verify_signed_seller_recovery(
                &plan.supplied_lock()?,
                &recipient,
                &funding,
                fee,
                signed,
            )
            .map(|verified| verified.transaction()),
        }
    }

    fn terminate_prepared(&self, stage: ShakedexValueStage) -> Result<Self, ShakedexError> {
        if self.stage != ShakedexValueStage::Prepared
            || self.authorized.is_some()
            || !matches!(
                stage,
                ShakedexValueStage::Expired | ShakedexValueStage::Cancelled
            )
        {
            return Err(ShakedexError::InvalidTransition);
        }
        let mut next = self.clone();
        next.stage = stage;
        next.validate()?;
        Ok(next)
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.workflow_id == other.workflow_id
            && self.action == other.action
            && self.structural_plan == other.structural_plan
            && self.structural_plan_commitment == other.structural_plan_commitment
            && self.funding_reservation == other.funding_reservation
            && self.source_coin == other.source_coin
            && self.funding_input_coins == other.funding_input_coins
            && self.recipient == other.recipient
            && self.value_base_units == other.value_base_units
            && self.fee_base_units == other.fee_base_units
            && self.maximum_fee == other.maximum_fee
            && self.minimum_confirmations == other.minimum_confirmations
            && self.prepared_transaction == other.prepared_transaction
            && self.expires_at_unix == other.expires_at_unix
    }

    fn same_authorization_identity(&self, other: &Self) -> bool {
        match (self.authorized.as_ref(), other.authorized.as_ref()) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.approval_id == right.approval_id
                    && left.transaction == right.transaction
                    && left.transaction_bytes == right.transaction_bytes
                    && left.authorized_at_unix == right.authorized_at_unix
            }
            _ => false,
        }
    }
}

#[derive(Serialize)]
struct ShakedexValueApprovalCommitment<'a> {
    domain: &'static str,
    revision: u64,
    workflow: &'a ShakedexValueWorkflow,
}

/// Derives the distinct persisted value-workflow key for one structural plan.
/// This prevents the aggregate transaction journal from replacing its parent
/// seller/buyer plan in the store's workflow primary-key namespace.
pub fn shakedex_value_workflow_id(
    parent_workflow_id: WorkflowId,
    action: ShakedexValueAction,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-value-workflow/v1");
    hasher.update(parent_workflow_id.as_bytes());
    hasher.update([match action {
        ShakedexValueAction::BuyerFulfillment => 0,
        ShakedexValueAction::SellerRecovery => 1,
    }]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredShakedexValueWorkflow {
    pub revision: u64,
    pub workflow: ShakedexValueWorkflow,
}

pub fn save_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    workflow: &ShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let updated_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    workflow.validate()?;
    if workflow.stage != ShakedexValueStage::Prepared
        || workflow.authorized.is_some()
        || updated_at_unix >= workflow.expires_at_unix
        || workflow.expires_at_unix
            > updated_at_unix.saturating_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let (wallet_id, account_id) = workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    let supplied_lock = workflow.supplied_lock()?;
    let current_lock = runtime.verify_current_shakedex_lock(
        &supplied_lock.descriptor().name,
        supplied_lock.descriptor().seller_public_key,
    )?;
    workflow.validate_current_lock(&current_lock)?;
    if runtime.validate_current_shakedex_funding_reservation(
        &current_lock,
        workflow.funding_reservation(),
    )? != *scope
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if let Some(current) = load_shakedex_value_workflow(store, workflow.workflow_id)? {
        if current.workflow != *workflow {
            return Err(ShakedexError::InvalidTransition);
        }
        validate_hns_shakedex_funding_reservations(
            store,
            scope,
            workflow.funding_reservation(),
            HnsShakedexFundingReservationState::Prepared,
        )?;
        return Ok(current);
    }
    let batch = create_hns_shakedex_funding_reservations(
        store,
        scope,
        workflow.funding_reservation(),
        updated_at_unix,
    )?;
    if !batch.deletes().is_empty() || batch.saves().is_empty() {
        return Err(ShakedexError::Invariant);
    }
    let revision = store.save_workflow_with_entity_batch(
        workflow.workflow_id,
        WorkflowKind::ShakedexValue,
        0,
        workflow,
        false,
        updated_at_unix,
        EntityKind::InputReservation,
        batch.saves(),
        batch.deletes(),
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: workflow.clone(),
    })
}

pub fn register_shakedex_value_approval<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    stored: &StoredShakedexValueWorkflow,
    approval_id: ApprovalId,
    origin: &str,
    expires_at_unix: u64,
) -> Result<(), ShakedexError> {
    let now_unix = runtime.shakedex_now_unix()?;
    stored.workflow.validate()?;
    require_exact_stored_value_workflow(store, stored)?;
    let runtime_scope = runtime.shakedex_funding_scope()?;
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if runtime_scope.wallet_id() != wallet_id || runtime_scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    if stored.workflow.stage != ShakedexValueStage::Prepared
        || now_unix >= expires_at_unix
        || expires_at_unix > stored.workflow.expires_at_unix
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let commitment = stored.workflow.approval_commitment(stored.revision)?;
    store.put_pending_approval(approval_id, origin, &commitment, now_unix, expires_at_unix)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
    current_lock: &VerifiedCurrentShakedexLock,
    approval_id: ApprovalId,
    origin: &str,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_value_runtime_release_qualified()?;
    let authorized_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    stored.workflow.validate()?;
    require_exact_stored_value_workflow(store, stored)?;
    stored.workflow.validate_current_lock(current_lock)?;
    if stored.workflow.stage != ShakedexValueStage::Prepared
        || authorized_at_unix >= stored.workflow.expires_at_unix
    {
        return Err(ShakedexError::InvalidTransition);
    }
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        HnsShakedexFundingReservationState::Prepared,
    )?;
    let approval = store
        .get_pending_approval(approval_id, authorized_at_unix)?
        .ok_or(ShakedexError::ApprovalRequired)?;
    let commitment = stored.workflow.approval_commitment(stored.revision)?;
    if approval.origin != origin || approval.request_json.as_slice() != commitment {
        return Err(ShakedexError::ApprovalRequired);
    }
    let expectation = HnsShakedexFundingApprovalExpectation::new(
        approval_id,
        origin.to_owned(),
        commitment,
        approval.expires_at_unix,
    )?;
    let authorization = runtime.authorize_shakedex_funding_suffix(
        current_lock,
        stored.workflow.funding_reservation(),
        &stored.workflow.prepared_transaction,
        &expectation,
    )?;
    let (signed_transaction, pending_approval) = authorization.into_parts();
    if pending_approval.id != approval.id
        || pending_approval.origin != approval.origin
        || pending_approval.request_json.as_slice() != approval.request_json.as_slice()
        || pending_approval.expires_at_unix != approval.expires_at_unix
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let input_coins = stored.workflow.all_input_coins()?;
    let quote = runtime.backend().quote_transaction_fee(
        &signed_transaction,
        &input_coins,
        DEFAULT_FEE_TARGET_BLOCKS,
        current_lock.binding(),
        current_lock.mempool_binding(),
    )?;
    validate_hns_shakedex_final_fee_quote_evidence(
        current_lock,
        stored.workflow.funding_reservation(),
        &signed_transaction,
        &quote,
        stored.workflow.fee_base_units,
        stored.workflow.maximum_fee,
    )?;
    require_exact_stored_value_workflow(store, stored)?;
    let commit_now = runtime.shakedex_now_unix()?;
    if commit_now < authorized_at_unix
        || commit_now >= stored.workflow.expires_at_unix
        || commit_now >= pending_approval.expires_at_unix
    {
        return Err(ShakedexError::ApprovalRequired);
    }
    let next = stored
        .workflow
        .authorize(approval_id, signed_transaction, quote, commit_now)?;
    let batch = activate_hns_shakedex_funding_reservations(
        store,
        scope,
        next.funding_reservation(),
        commit_now,
    )?;
    let revision = store
        .consume_approval_and_save_workflow_with_entity_batch(
            &pending_approval,
            commit_now,
            next.workflow_id,
            WorkflowKind::ShakedexValue,
            stored.revision,
            &next,
            true,
            EntityKind::InputReservation,
            batch.saves(),
            batch.deletes(),
        )?
        .ok_or(ShakedexError::ApprovalRequired)?;
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        next.funding_reservation(),
        HnsShakedexFundingReservationState::Active,
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: next,
    })
}

pub fn cancel_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let cancelled_at_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    terminate_prepared_value_workflow(
        store,
        scope,
        stored,
        ShakedexValueStage::Cancelled,
        cancelled_at_unix,
    )
}

pub fn expire_prepared_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    let now_unix = runtime.shakedex_now_unix()?;
    validate_runtime_scope(runtime, scope)?;
    if now_unix < stored.workflow.expires_at_unix {
        return Err(ShakedexError::InvalidTransition);
    }
    terminate_prepared_value_workflow(store, scope, stored, ShakedexValueStage::Expired, now_unix)
}

pub fn submit_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_value_runtime_release_qualified()?;
    if stored.workflow.stage != ShakedexValueStage::Authorized {
        return Err(ShakedexError::InvalidTransition);
    }
    submit_value_workflow(store, runtime, scope, stored)
}

pub fn rebroadcast_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_value_runtime_release_qualified()?;
    if stored.workflow.stage != ShakedexValueStage::RequiresRebroadcast {
        return Err(ShakedexError::InvalidTransition);
    }
    submit_value_workflow(store, runtime, scope, stored)
}

fn terminate_prepared_value_workflow(
    store: &mut WalletStore,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
    stage: ShakedexValueStage,
    updated_at_unix: u64,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    require_exact_stored_value_workflow(store, stored)?;
    let next = stored.workflow.terminate_prepared(stage)?;
    let batch = delete_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        HnsShakedexFundingReservationState::Prepared,
    )?;
    if !batch.saves().is_empty() || batch.deletes().is_empty() {
        return Err(ShakedexError::Invariant);
    }
    let revision = store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
        next.workflow_id,
        WorkflowKind::ShakedexValue,
        stored.revision,
        &next,
        false,
        updated_at_unix,
        EntityKind::InputReservation,
        batch.saves(),
        batch.deletes(),
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: next,
    })
}

fn submit_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    stored.workflow.validate()?;
    validate_runtime_scope(runtime, scope)?;
    require_exact_stored_value_workflow(store, stored)?;
    let supplied_lock = stored.workflow.supplied_lock()?;
    let current_lock = runtime.verify_current_shakedex_lock(
        &supplied_lock.descriptor().name,
        supplied_lock.descriptor().seller_public_key,
    )?;
    stored.workflow.validate_current_lock(&current_lock)?;
    validate_shakedex_value_workflow_reservations(store, scope, stored)?;
    let signed = stored
        .workflow
        .signed_transaction()
        .ok_or(ShakedexError::InvalidTransition)?;
    let input_coins = stored.workflow.all_input_coins()?;
    let refreshed_quote = runtime.backend().quote_transaction_fee(
        signed,
        &input_coins,
        DEFAULT_FEE_TARGET_BLOCKS,
        current_lock.binding(),
        current_lock.mempool_binding(),
    )?;
    validate_hns_shakedex_final_fee_quote_evidence(
        &current_lock,
        stored.workflow.funding_reservation(),
        signed,
        &refreshed_quote,
        stored.workflow.fee_base_units,
        stored.workflow.maximum_fee,
    )?;
    let fence_lock = runtime.verify_current_shakedex_lock(
        &supplied_lock.descriptor().name,
        supplied_lock.descriptor().seller_public_key,
    )?;
    stored.workflow.validate_current_lock(&fence_lock)?;
    if fence_lock.binding() != refreshed_quote.binding
        || fence_lock.mempool_binding() != refreshed_quote.mempool
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let submission_started_at_unix = runtime.shakedex_now_unix()?;
    let fenced = stored
        .workflow
        .begin_submission(refreshed_quote, submission_started_at_unix)?;
    let reservation_batch = retain_active_hns_shakedex_funding_reservations(
        store,
        scope,
        fenced.funding_reservation(),
        submission_started_at_unix,
    )?;
    if reservation_batch.saves().is_empty() || !reservation_batch.deletes().is_empty() {
        return Err(ShakedexError::Invariant);
    }
    fenced.validate()?;
    if validate_save_transition(store, stored.revision, &fenced)?.is_some() {
        return Err(ShakedexError::InvalidTransition);
    }
    let fenced_revision = store.save_workflow_with_entity_batch(
        fenced.workflow_id,
        WorkflowKind::ShakedexValue,
        stored.revision,
        &fenced,
        true,
        submission_started_at_unix,
        EntityKind::InputReservation,
        reservation_batch.saves(),
        reservation_batch.deletes(),
    )?;
    let returned_transaction = runtime.backend().broadcast_transaction(
        fenced
            .signed_transaction()
            .ok_or(ShakedexError::Invariant)?,
    )?;
    let accepted_at_unix = runtime.shakedex_now_unix()?;
    let submitted = fenced.record_broadcast(returned_transaction, accepted_at_unix)?;
    let revision = save_value_workflow(store, fenced_revision, &submitted, accepted_at_unix)?;
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        submitted.funding_reservation(),
        HnsShakedexFundingReservationState::Active,
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: submitted,
    })
}

fn require_value_runtime_release_qualified() -> Result<(), ShakedexError> {
    if !SHAKEDEX_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_SHAKEDEX_FUNDING_RELEASE_QUALIFIED
        || !HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
        || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
    {
        return Err(ShakedexError::ValueRuntimeUnavailable);
    }
    Ok(())
}

pub fn reconcile_shakedex_value_workflow<B: HnsBackend, C: HnsClock>(
    store: &mut WalletStore,
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    validate_runtime_scope(runtime, scope)?;
    require_exact_stored_value_workflow(store, stored)?;
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        HnsShakedexFundingReservationState::Active,
    )?;
    let signed = stored
        .workflow
        .signed_transaction()
        .ok_or(ShakedexError::InvalidTransition)?;
    let observation =
        runtime.observe_shakedex_transaction(stored.workflow.funding_reservation(), signed)?;
    if observation.transaction()
        != stored
            .workflow
            .transaction()
            .ok_or(ShakedexError::InvalidTransition)?
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let observed_at_unix = observation.observed_at_unix();
    let (transaction_evidence, spend_evidence) = observation.into_parts();
    let next =
        stored
            .workflow
            .reconcile(&transaction_evidence, &spend_evidence, observed_at_unix)?;
    let reservation_batch = retain_active_hns_shakedex_funding_reservations(
        store,
        scope,
        next.funding_reservation(),
        observed_at_unix,
    )?;
    if reservation_batch.saves().is_empty() || !reservation_batch.deletes().is_empty() {
        return Err(ShakedexError::Invariant);
    }
    let revision = match validate_save_transition(store, stored.revision, &next)? {
        Some(revision) => revision,
        None => store.save_workflow_with_entity_batch(
            next.workflow_id,
            WorkflowKind::ShakedexValue,
            stored.revision,
            &next,
            true,
            observed_at_unix,
            EntityKind::InputReservation,
            reservation_batch.saves(),
            reservation_batch.deletes(),
        )?,
    };
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        next.funding_reservation(),
        HnsShakedexFundingReservationState::Active,
    )?;
    Ok(StoredShakedexValueWorkflow {
        revision,
        workflow: next,
    })
}

pub fn load_shakedex_value_workflow(
    store: &WalletStore,
    workflow_id: WorkflowId,
) -> Result<Option<StoredShakedexValueWorkflow>, ShakedexError> {
    store
        .load_workflow::<ShakedexValueWorkflow>(workflow_id)?
        .map(validate_stored_value_workflow)
        .transpose()
}

/// Reauthenticate the exact reservation rows required by a loaded aggregate.
/// Terminal pre-authorization workflows must have released every row; signed
/// workflows retain both source and funding reservations through reorgs.
pub fn validate_shakedex_value_workflow_reservations(
    store: &WalletStore,
    scope: &HnsShakedexFundingScope,
    stored: &StoredShakedexValueWorkflow,
) -> Result<(), ShakedexError> {
    stored.workflow.validate()?;
    let (wallet_id, account_id) = stored.workflow.wallet_and_account();
    if scope.wallet_id() != wallet_id || scope.account_id() != account_id {
        return Err(ShakedexError::InvalidEvidence);
    }
    let expected_state = match stored.workflow.stage {
        ShakedexValueStage::Prepared => HnsShakedexFundingReservationState::Prepared,
        ShakedexValueStage::Expired | ShakedexValueStage::Cancelled => {
            HnsShakedexFundingReservationState::Released
        }
        ShakedexValueStage::Authorized
        | ShakedexValueStage::RequiresRebroadcast
        | ShakedexValueStage::Broadcast
        | ShakedexValueStage::Mempool
        | ShakedexValueStage::Confirming
        | ShakedexValueStage::Confirmed
        | ShakedexValueStage::Conflicted => HnsShakedexFundingReservationState::Active,
    };
    validate_hns_shakedex_funding_reservations(
        store,
        scope,
        stored.workflow.funding_reservation(),
        expected_state,
    )?;
    Ok(())
}

fn validate_runtime_scope<B: HnsBackend, C: HnsClock>(
    runtime: &HnsWalletRuntime<B, C>,
    scope: &HnsShakedexFundingScope,
) -> Result<(), ShakedexError> {
    if runtime.shakedex_funding_scope()? != *scope {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn require_exact_stored_value_workflow(
    store: &WalletStore,
    supplied: &StoredShakedexValueWorkflow,
) -> Result<(), ShakedexError> {
    let current = load_shakedex_value_workflow(store, supplied.workflow.workflow_id)?
        .ok_or(ShakedexError::InvalidTransition)?;
    if current.revision != supplied.revision {
        return Err(ShakedexError::StaleRevision);
    }
    if current.workflow != supplied.workflow {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

pub fn list_shakedex_value_workflows(
    store: &WalletStore,
) -> Result<Vec<StoredShakedexValueWorkflow>, ShakedexError> {
    store
        .list_workflows_complete::<ShakedexValueWorkflow>(
            WorkflowKind::ShakedexValue,
            MAX_SHAKEDEX_VALUE_WORKFLOWS,
        )?
        .into_iter()
        .map(validate_stored_value_workflow)
        .collect()
}

pub(crate) fn save_value_workflow(
    store: &mut WalletStore,
    expected_revision: u64,
    workflow: &ShakedexValueWorkflow,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    workflow.validate()?;
    if let Some(revision) = validate_save_transition(store, expected_revision, workflow)? {
        return Ok(revision);
    }
    store
        .save_workflow(
            workflow.workflow_id,
            WorkflowKind::ShakedexValue,
            expected_revision,
            workflow,
            workflow.authorized.is_some(),
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}

fn validate_stored_value_workflow(
    stored: StoredWorkflow<ShakedexValueWorkflow>,
) -> Result<StoredShakedexValueWorkflow, ShakedexError> {
    if stored.kind != WorkflowKind::ShakedexValue
        || stored.id != stored.state.workflow_id
        || stored.irreversible_broadcast_prepared != stored.state.authorized.is_some()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    stored.state.validate()?;
    Ok(StoredShakedexValueWorkflow {
        revision: stored.revision,
        workflow: stored.state,
    })
}

fn validate_save_transition(
    store: &WalletStore,
    expected_revision: u64,
    next: &ShakedexValueWorkflow,
) -> Result<Option<u64>, ShakedexError> {
    let Some(current) = load_shakedex_value_workflow(store, next.workflow_id)? else {
        if expected_revision != 0 || next.stage != ShakedexValueStage::Prepared {
            return Err(ShakedexError::InvalidTransition);
        }
        return Ok(None);
    };
    if current.workflow == *next
        && (expected_revision == current.revision
            || expected_revision.checked_add(1) == Some(current.revision))
    {
        return Ok(Some(current.revision));
    }
    if current.revision != expected_revision {
        return Err(ShakedexError::StaleRevision);
    }
    if !current.workflow.same_identity(next) {
        return Err(ShakedexError::InvalidEvidence);
    }
    if current.workflow.authorized.is_some() && !current.workflow.same_authorization_identity(next)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if next.submission_attempts < current.workflow.submission_attempts
        || current.workflow.confirmed_once && !next.confirmed_once
        || current.workflow.conflicted_once && !next.conflicted_once
        || matches!(
            (
                current.workflow.submission_started_at_unix,
                next.submission_started_at_unix,
            ),
            (Some(current), Some(next)) if next < current
        )
        || matches!(
            (
                current.workflow.last_chain_observation.as_ref(),
                next.last_chain_observation.as_ref(),
            ),
            (Some(current), Some(next))
                if next.observed_at_unix < current.observed_at_unix
                    || !snapshot_binding_not_older(next.binding, current.binding)
                    || !mempool_binding_not_older(next.mempool, current.mempool)
        )
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    if !valid_stage_transition(current.workflow.stage, next.stage) {
        return Err(ShakedexError::InvalidTransition);
    }
    Ok(None)
}

fn valid_stage_transition(current: ShakedexValueStage, next: ShakedexValueStage) -> bool {
    matches!(
        (current, next),
        (
            ShakedexValueStage::RequiresRebroadcast
                | ShakedexValueStage::Mempool
                | ShakedexValueStage::Confirming
                | ShakedexValueStage::Confirmed
                | ShakedexValueStage::Conflicted,
            same,
        ) if current == same
    ) || matches!(
        (current, next),
        (ShakedexValueStage::Prepared, ShakedexValueStage::Authorized)
            | (ShakedexValueStage::Prepared, ShakedexValueStage::Expired)
            | (ShakedexValueStage::Prepared, ShakedexValueStage::Cancelled)
            | (
                ShakedexValueStage::Authorized
                    | ShakedexValueStage::RequiresRebroadcast
                    | ShakedexValueStage::Broadcast
                    | ShakedexValueStage::Mempool
                    | ShakedexValueStage::Conflicted,
                ShakedexValueStage::RequiresRebroadcast
            )
            | (
                ShakedexValueStage::RequiresRebroadcast,
                ShakedexValueStage::Broadcast
            )
            | (
                ShakedexValueStage::Authorized
                    | ShakedexValueStage::RequiresRebroadcast
                    | ShakedexValueStage::Broadcast
                    | ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted,
                ShakedexValueStage::Mempool
                    | ShakedexValueStage::Confirming
                    | ShakedexValueStage::Confirmed
                    | ShakedexValueStage::Conflicted
            )
            | (
                ShakedexValueStage::Confirming | ShakedexValueStage::Confirmed,
                ShakedexValueStage::RequiresRebroadcast
            )
    )
}

fn structural_plan_commitment(plan: &StructuralPlan) -> Result<ObjectHash, ShakedexError> {
    let encoded = serde_json::to_vec(plan).map_err(|_| ShakedexError::Encoding)?;
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/shakedex-structural-plan/v1");
    hasher.update(encoded);
    Ok(ObjectHash::new(hasher.finalize().into()))
}

fn canonical_transaction(raw: &[u8]) -> Result<Transaction, ShakedexError> {
    let transaction = Transaction::decode(raw).map_err(|_| ShakedexError::InvalidEvidence)?;
    if transaction
        .encode()
        .map_err(|_| ShakedexError::InvalidEvidence)?
        != raw
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(transaction)
}

fn require_only_funding_witness_changes(
    prepared_raw: &[u8],
    signed_raw: &[u8],
) -> Result<(), ShakedexError> {
    let prepared = canonical_transaction(prepared_raw)?;
    let signed = canonical_transaction(signed_raw)?;
    if prepared.version != signed.version
        || prepared.outputs != signed.outputs
        || prepared.locktime != signed.locktime
        || prepared.inputs.len() != signed.inputs.len()
        || prepared.inputs[0] != signed.inputs[0]
        || prepared.inputs[1..]
            .iter()
            .zip(&signed.inputs[1..])
            .any(|(left, right)| {
                left.previous_output != right.previous_output
                    || left.sequence != right.sequence
                    || !left.witness.items.is_empty()
                    || right.witness.items.is_empty()
            })
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn validate_transaction_evidence(
    workflow: &ShakedexValueWorkflow,
    evidence: &TransactionEvidence,
) -> Result<(), ShakedexError> {
    let quote = workflow
        .fee_quote()
        .ok_or(ShakedexError::InvalidTransition)?;
    let confirmation_count_matches = match evidence.inclusion {
        Some(inclusion) => {
            inclusion.height <= evidence.binding.tip.height
                && evidence.status.confirmation_count
                    == u32::try_from(
                        evidence
                            .binding
                            .tip
                            .height
                            .checked_sub(inclusion.height)
                            .and_then(|depth| depth.checked_add(1))
                            .ok_or(ShakedexError::InvalidEvidence)?,
                    )
                    .map_err(|_| ShakedexError::InvalidEvidence)?
        }
        None => evidence.status.confirmation_count == 0,
    };
    if evidence
        .raw
        .as_deref()
        .is_some_and(|raw| workflow.signed_transaction() != Some(raw))
        || !snapshot_binding_not_older(evidence.binding, quote.binding)
        || !mempool_binding_not_older(evidence.mempool, quote.mempool)
        || !confirmation_count_matches
        || evidence.status.confirmation_count > 0 && evidence.inclusion.is_none()
        || evidence.status.confirmation_count == 0 && evidence.inclusion.is_some()
        || evidence.status.conflicted
            && (evidence.status.in_mempool || evidence.status.confirmation_count > 0)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn snapshot_binding_not_older(candidate: SnapshotBinding, floor: SnapshotBinding) -> bool {
    candidate.chain_epoch > floor.chain_epoch
        || candidate.chain_epoch == floor.chain_epoch
            && (candidate.tip.height > floor.tip.height || candidate.tip == floor.tip)
}

fn mempool_binding_not_older(
    candidate: MempoolSnapshotBinding,
    floor: MempoolSnapshotBinding,
) -> bool {
    candidate.instance_nonce != floor.instance_nonce || candidate.generation >= floor.generation
}

fn submission_evidence_not_older(
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    started_at_unix: u64,
    observation: &ShakedexChainObservation,
) -> bool {
    started_at_unix >= observation.observed_at_unix
        && snapshot_binding_not_older(binding, observation.binding)
        && mempool_binding_not_older(mempool, observation.mempool)
}

fn validate_spend_evidence(
    workflow: &ShakedexValueWorkflow,
    evidence: &OutpointSpendEvidence,
    expected_transaction: TransactionHash,
    transaction_evidence: &TransactionEvidence,
) -> Result<Vec<TransactionHash>, ShakedexError> {
    let transaction = canonical_transaction(
        workflow
            .signed_transaction()
            .ok_or(ShakedexError::InvalidTransition)?,
    )?;
    if evidence.binding != transaction_evidence.binding
        || evidence.entries.len() != transaction.inputs.len()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let mut competing: std::collections::BTreeMap<
        TransactionHash,
        (u64, [u8; 32], std::collections::BTreeSet<u32>),
    > = std::collections::BTreeMap::new();
    for (index, (input, entry)) in transaction.inputs.iter().zip(&evidence.entries).enumerate() {
        if entry.outpoint.transaction.as_bytes()
            != input.previous_output.transaction_hash.as_bytes()
            || entry.outpoint.output_index != input.previous_output.index
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        if let Some(spending) = entry.spending {
            if spending.height > evidence.binding.tip.height {
                return Err(ShakedexError::InvalidEvidence);
            }
            if spending.transaction == expected_transaction {
                let inclusion = transaction_evidence
                    .inclusion
                    .ok_or(ShakedexError::InvalidEvidence)?;
                if transaction_evidence.status.conflicted
                    || transaction_evidence.status.confirmation_count == 0
                    || spending.input_position
                        != u32::try_from(index).map_err(|_| ShakedexError::InvalidEvidence)?
                    || spending.height != inclusion.height
                    || spending.block_hash != inclusion.block_hash
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            } else {
                if transaction_evidence.status.in_mempool
                    || transaction_evidence.status.confirmation_count > 0
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
                let observed = competing.entry(spending.transaction).or_insert_with(|| {
                    (
                        spending.height,
                        spending.block_hash,
                        std::collections::BTreeSet::new(),
                    )
                });
                if observed.0 != spending.height
                    || observed.1 != spending.block_hash
                    || !observed.2.insert(spending.input_position)
                {
                    return Err(ShakedexError::InvalidEvidence);
                }
            }
        } else if transaction_evidence.status.confirmation_count > 0 {
            return Err(ShakedexError::InvalidEvidence);
        }
    }
    Ok(competing.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_wallet_hns::ChainTip;

    fn binding(epoch: u64, height: u64, hash: u8) -> SnapshotBinding {
        SnapshotBinding {
            tip: ChainTip {
                height,
                block_hash: [hash; 32],
                tree_root: [hash.wrapping_add(1); 32],
                median_time_past: 1_800_000_000 + height,
            },
            chain_epoch: epoch,
        }
    }

    #[test]
    fn hns_shakedex_value_child_identity_and_reorg_transitions() {
        let parent = WorkflowId::new([0x41; 16]);
        let buyer = shakedex_value_workflow_id(parent, ShakedexValueAction::BuyerFulfillment);
        let seller = shakedex_value_workflow_id(parent, ShakedexValueAction::SellerRecovery);
        assert_ne!(buyer, parent);
        assert_ne!(seller, parent);
        assert_ne!(buyer, seller);
        assert_eq!(
            buyer,
            shakedex_value_workflow_id(parent, ShakedexValueAction::BuyerFulfillment)
        );

        assert!(valid_stage_transition(
            ShakedexValueStage::Conflicted,
            ShakedexValueStage::RequiresRebroadcast
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Conflicted,
            ShakedexValueStage::Confirmed
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Authorized,
            ShakedexValueStage::RequiresRebroadcast
        ));
        assert!(valid_stage_transition(
            ShakedexValueStage::Authorized,
            ShakedexValueStage::Mempool
        ));
        assert!(!valid_stage_transition(
            ShakedexValueStage::Confirmed,
            ShakedexValueStage::Authorized
        ));

        let floor = binding(7, 500, 0x51);
        assert!(snapshot_binding_not_older(floor, floor));
        assert!(!snapshot_binding_not_older(binding(7, 499, 0x50), floor));
        assert!(!snapshot_binding_not_older(binding(7, 500, 0x52), floor));
        assert!(snapshot_binding_not_older(binding(8, 480, 0x53), floor));

        let mempool = MempoolSnapshotBinding {
            instance_nonce: [0x61; 32],
            generation: 9,
        };
        assert!(!mempool_binding_not_older(
            MempoolSnapshotBinding {
                generation: 8,
                ..mempool
            },
            mempool
        ));
        assert!(mempool_binding_not_older(
            MempoolSnapshotBinding {
                instance_nonce: [0x62; 32],
                generation: 0,
            },
            mempool
        ));

        let observation = ShakedexChainObservation {
            binding: floor,
            mempool,
            inclusion: None,
            in_mempool: false,
            confirmation_count: 0,
            conflicted: false,
            observed_at_unix: 1_800_000_500,
        };
        assert!(!submission_evidence_not_older(
            binding(7, 499, 0x50),
            mempool,
            observation.observed_at_unix,
            &observation,
        ));
        assert!(!submission_evidence_not_older(
            floor,
            MempoolSnapshotBinding {
                generation: 8,
                ..mempool
            },
            observation.observed_at_unix,
            &observation,
        ));
        assert!(!submission_evidence_not_older(
            floor,
            mempool,
            observation.observed_at_unix - 1,
            &observation,
        ));
        assert!(submission_evidence_not_older(
            binding(8, 480, 0x53),
            MempoolSnapshotBinding {
                instance_nonce: [0x62; 32],
                generation: 0,
            },
            observation.observed_at_unix,
            &observation,
        ));
    }
}
