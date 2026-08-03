use hns_covenants::{CovenantKind, FinalizeCovenant, NameState, TransferCovenant};
use hns_primitives::BlockHash;
use hns_script::{K256SignatureVerifier, SIGHASH_ALL, ScriptFlags, verify_witness_program};
use hns_swap::{COMPACT_SIGNATURE_SIZE, NetworkBinding, ShakedexLockDescriptor};
use hns_transaction::{
    Address, Coin, Input, Output, Transaction, Witness, build_finalize_transaction,
    build_transfer_output, verify_covenant_links, verify_finalize_at_index_zero,
};
use hns_wallet_hns::{
    HnsShakedexSigner, VerifiedCurrentShakedexLock, VerifiedCurrentShakedexTransfer,
};
use hns_wallet_types::TransactionHash;

use crate::{AuthenticatedFixedPriceListing, ShakedexError, VerifiedFixedPriceListing};

pub const MAX_SHAKEDEX_FUNDING_INPUTS: usize = 512;

/// A canonical Shakedex lock authenticated only against a caller-supplied
/// coin. Private fields prevent fabrication after construction, but this type
/// deliberately does not claim that the coin is current or unspent.
#[derive(Clone)]
pub struct SuppliedShakedexLock {
    network: NetworkBinding,
    descriptor: ShakedexLockDescriptor,
    locking_coin: Coin,
}

impl SuppliedShakedexLock {
    pub fn verify(
        expected_network: NetworkBinding,
        locking_coin: Coin,
        seller_public_key: [u8; 33],
    ) -> Result<Self, ShakedexError> {
        let descriptor = ShakedexLockDescriptor::from_locking_coin(
            expected_network,
            &locking_coin,
            seller_public_key,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
        descriptor
            .verify_for_network(expected_network, &locking_coin)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        Ok(Self {
            network: expected_network,
            descriptor,
            locking_coin,
        })
    }

    pub const fn network(&self) -> NetworkBinding {
        self.network
    }

    pub const fn descriptor(&self) -> &ShakedexLockDescriptor {
        &self.descriptor
    }

    pub const fn locking_coin(&self) -> &Coin {
        &self.locking_coin
    }
}

fn supplied_lock_from_current(
    current: &VerifiedCurrentShakedexLock,
) -> Result<SuppliedShakedexLock, ShakedexError> {
    let descriptor = current.descriptor();
    let supplied = SuppliedShakedexLock::verify(
        descriptor.network,
        current.locking_coin().clone(),
        descriptor.seller_public_key,
    )?;
    if supplied.descriptor() != descriptor {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(supplied)
}

/// Unsigned buyer funding suffix around an already seller-signed canonical
/// fulfillment. A wallet must still sign inputs `1..` and reverify the result.
pub struct PreparedBuyerFulfillment {
    listing: AuthenticatedFixedPriceListing,
    supplied_lock: SuppliedShakedexLock,
    expected_recipient: Address,
    buyer_input_coins: Vec<Coin>,
    unsigned_transaction: Vec<u8>,
    fee_base_units: u64,
}

impl PreparedBuyerFulfillment {
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.unsigned_transaction
    }

    pub fn buyer_input_coins(&self) -> &[Coin] {
        &self.buyer_input_coins
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }

    pub fn verify_signed(
        &self,
        signed_transaction: &[u8],
    ) -> Result<VerifiedBuyerFulfillment, ShakedexError> {
        require_witness_only_suffix_change(&self.unsigned_transaction, signed_transaction)?;
        verify_signed_buyer_fulfillment(
            &self.listing,
            &self.supplied_lock,
            &self.expected_recipient,
            &self.buyer_input_coins,
            self.fee_base_units,
            signed_transaction,
        )
    }
}

/// Fully signed and locally verified fulfillment bytes. This remains
/// structural authority; a value runtime must independently prove current
/// chain state, fee policy, approval, and absence of a competing spend.
pub struct VerifiedBuyerFulfillment {
    transaction: TransactionHash,
    transaction_bytes: Vec<u8>,
    recipient: Address,
    fee_base_units: u64,
}

impl VerifiedBuyerFulfillment {
    pub const fn transaction(&self) -> TransactionHash {
        self.transaction
    }

    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    pub const fn recipient(&self) -> &Address {
        &self.recipient
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }
}

/// Build the exact fulfillment around wallet-selected ordinary funding.
/// `supplied_now_unix` and `supplied_parent_median_time` are structural
/// inputs, not authenticated wall or chain time; the HNS runtime must provide
/// snapshot-bound values later.
#[allow(clippy::too_many_arguments)]
pub fn prepare_buyer_fulfillment(
    listing: &VerifiedFixedPriceListing,
    supplied_lock: &SuppliedShakedexLock,
    supplied_now_unix: u64,
    supplied_parent_median_time: u64,
    expected_recipient: Address,
    buyer_inputs: Vec<Input>,
    buyer_input_coins: Vec<Coin>,
    buyer_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<PreparedBuyerFulfillment, ShakedexError> {
    crate::verify_fixed_price_listing(
        listing.encoded(),
        listing.listing_hash(),
        supplied_lock.network(),
        supplied_now_unix,
        supplied_lock.locking_coin(),
    )?;
    bind_listing_to_lock(listing.authenticated(), supplied_lock)?;
    if !listing
        .proof()
        .is_executable(supplied_parent_median_time)
        .map_err(|_| ShakedexError::InvalidEvidence)?
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    validate_funding_suffix(
        &buyer_inputs,
        &buyer_input_coins,
        supplied_lock.locking_coin(),
    )?;
    validate_funding_outputs(&buyer_outputs)?;
    let transaction = listing
        .proof()
        .fulfillment_transaction(
            supplied_lock.locking_coin(),
            &expected_recipient,
            buyer_inputs,
            buyer_outputs,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    verify_fulfillment_structure(
        listing.authenticated(),
        supplied_lock,
        &expected_recipient,
        &buyer_input_coins,
        expected_fee_base_units,
        &transaction,
        false,
    )?;
    let unsigned_transaction = canonical_transaction_bytes(&transaction)?;
    let listing =
        crate::authenticate_fixed_price_listing(listing.encoded(), listing.listing_hash())?;
    Ok(PreparedBuyerFulfillment {
        listing,
        supplied_lock: supplied_lock.clone(),
        expected_recipient,
        buyer_input_coins,
        unsigned_transaction,
        fee_base_units: expected_fee_base_units,
    })
}

/// Build a buyer fulfillment from an HNS-runtime authority that has already
/// bound the exact lock, active NameState, confirmed/mempool unspentness, and
/// parent median time to one current snapshot.
#[allow(clippy::too_many_arguments)]
pub fn prepare_current_buyer_fulfillment(
    listing: &VerifiedFixedPriceListing,
    current_lock: &VerifiedCurrentShakedexLock,
    now_unix: u64,
    expected_recipient: Address,
    buyer_inputs: Vec<Input>,
    buyer_input_coins: Vec<Coin>,
    buyer_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<PreparedBuyerFulfillment, ShakedexError> {
    let supplied_lock = supplied_lock_from_current(current_lock)?;
    prepare_buyer_fulfillment(
        listing,
        &supplied_lock,
        now_unix,
        current_lock.parent_median_time(),
        expected_recipient,
        buyer_inputs,
        buyer_input_coins,
        buyer_outputs,
        expected_fee_base_units,
    )
}

pub fn verify_signed_buyer_fulfillment(
    listing: &AuthenticatedFixedPriceListing,
    supplied_lock: &SuppliedShakedexLock,
    expected_recipient: &Address,
    buyer_input_coins: &[Coin],
    expected_fee_base_units: u64,
    signed_transaction: &[u8],
) -> Result<VerifiedBuyerFulfillment, ShakedexError> {
    bind_listing_to_lock(listing, supplied_lock)?;
    let transaction = decode_canonical_transaction(signed_transaction)?;
    verify_fulfillment_structure(
        listing,
        supplied_lock,
        expected_recipient,
        buyer_input_coins,
        expected_fee_base_units,
        &transaction,
        true,
    )?;
    Ok(VerifiedBuyerFulfillment {
        transaction: wallet_transaction_hash(&transaction)?,
        transaction_bytes: signed_transaction.to_vec(),
        recipient: expected_recipient.clone(),
        fee_base_units: expected_fee_base_units,
    })
}

/// Recovery transaction with the exact seller digest still awaiting its
/// purpose-bound `HnsShakedex` signature.
pub struct PreparedSellerRecovery {
    supplied_lock: SuppliedShakedexLock,
    recovery_recipient: Address,
    funding_input_coins: Vec<Coin>,
    unsigned_transaction: Transaction,
    recovery_signature_hash: [u8; 32],
    fee_base_units: u64,
}

impl PreparedSellerRecovery {
    pub fn transaction_bytes(&self) -> Result<Vec<u8>, ShakedexError> {
        canonical_transaction_bytes(&self.unsigned_transaction)
    }

    pub const fn recovery_signature_hash(&self) -> &[u8; 32] {
        &self.recovery_signature_hash
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }

    /// Authorize the exact prepared recovery through the allocation-bound HNS
    /// signer without exposing either the scalar or an arbitrary digest API.
    fn authorize_with_hns_signer(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        signer: &HnsShakedexSigner,
    ) -> Result<SellerAuthorizedRecovery, ShakedexError> {
        let mut transaction = self.unsigned_transaction.clone();
        signer
            .sign_current_recovery_transaction(
                current_lock,
                &mut transaction,
                &self.recovery_recipient,
            )
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        Ok(SellerAuthorizedRecovery {
            supplied_lock: self.supplied_lock.clone(),
            recovery_recipient: self.recovery_recipient.clone(),
            funding_input_coins: self.funding_input_coins.clone(),
            seller_authorized_transaction: canonical_transaction_bytes(&transaction)?,
            fee_base_units: self.fee_base_units,
        })
    }

    pub fn install_seller_signature(
        &self,
        signature: &[u8; COMPACT_SIGNATURE_SIZE],
    ) -> Result<SellerAuthorizedRecovery, ShakedexError> {
        let mut transaction = self.unsigned_transaction.clone();
        transaction.inputs[0].witness = self
            .supplied_lock
            .descriptor()
            .recovery_witness(signature)
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        self.supplied_lock
            .descriptor()
            .verify_recovery(
                &transaction,
                self.supplied_lock.locking_coin(),
                &self.recovery_recipient,
            )
            .map_err(|_| ShakedexError::InvalidEvidence)?;
        Ok(SellerAuthorizedRecovery {
            supplied_lock: self.supplied_lock.clone(),
            recovery_recipient: self.recovery_recipient.clone(),
            funding_input_coins: self.funding_input_coins.clone(),
            seller_authorized_transaction: canonical_transaction_bytes(&transaction)?,
            fee_base_units: self.fee_base_units,
        })
    }
}

/// Recovery prepared from current-chain authority. Seller authorization
/// requires the current authority for the same exact lock again, so a generic
/// caller-supplied structural preparation cannot reach the protected HNS
/// signer. The enclosing value runtime remains responsible for reacquisition
/// before irreversible use.
pub struct CurrentPreparedSellerRecovery {
    inner: PreparedSellerRecovery,
}

impl CurrentPreparedSellerRecovery {
    pub fn transaction_bytes(&self) -> Result<Vec<u8>, ShakedexError> {
        self.inner.transaction_bytes()
    }

    pub const fn recovery_signature_hash(&self) -> &[u8; 32] {
        self.inner.recovery_signature_hash()
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.inner.fee_base_units()
    }

    pub fn authorize_with_hns_signer(
        &self,
        current_lock: &VerifiedCurrentShakedexLock,
        signer: &HnsShakedexSigner,
    ) -> Result<SellerAuthorizedRecovery, ShakedexError> {
        let current = supplied_lock_from_current(current_lock)?;
        if current.descriptor() != self.inner.supplied_lock.descriptor()
            || current.locking_coin() != self.inner.supplied_lock.locking_coin()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        self.inner.authorize_with_hns_signer(current_lock, signer)
    }
}

/// Seller-authorized recovery awaiting ordinary funding-input signatures.
pub struct SellerAuthorizedRecovery {
    supplied_lock: SuppliedShakedexLock,
    recovery_recipient: Address,
    funding_input_coins: Vec<Coin>,
    seller_authorized_transaction: Vec<u8>,
    fee_base_units: u64,
}

impl SellerAuthorizedRecovery {
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.seller_authorized_transaction
    }

    pub fn funding_input_coins(&self) -> &[Coin] {
        &self.funding_input_coins
    }

    pub fn verify_signed(
        &self,
        signed_transaction: &[u8],
    ) -> Result<VerifiedSellerRecovery, ShakedexError> {
        require_witness_only_suffix_change(
            &self.seller_authorized_transaction,
            signed_transaction,
        )?;
        verify_signed_seller_recovery(
            &self.supplied_lock,
            &self.recovery_recipient,
            &self.funding_input_coins,
            self.fee_base_units,
            signed_transaction,
        )
    }
}

pub struct VerifiedSellerRecovery {
    transaction: TransactionHash,
    transaction_bytes: Vec<u8>,
    recipient: Address,
    fee_base_units: u64,
}

impl VerifiedSellerRecovery {
    pub const fn transaction(&self) -> TransactionHash {
        self.transaction
    }

    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    pub const fn recipient(&self) -> &Address {
        &self.recipient
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }
}

/// A fully verified Shakedex TRANSFER whose canonical transaction may supply
/// the exact output-zero lineage for a later script-controlled FINALIZE.
/// Callers cannot fabricate either verified variant because their fields are
/// private and their constructors perform full structural witness checks.
#[derive(Clone, Copy)]
pub enum VerifiedShakedexTransfer<'a> {
    Fulfillment(&'a VerifiedBuyerFulfillment),
    Recovery(&'a VerifiedSellerRecovery),
}

impl<'a> VerifiedShakedexTransfer<'a> {
    const fn transaction(self) -> TransactionHash {
        match self {
            Self::Fulfillment(transaction) => transaction.transaction(),
            Self::Recovery(transaction) => transaction.transaction(),
        }
    }

    fn transaction_bytes(self) -> &'a [u8] {
        match self {
            Self::Fulfillment(transaction) => transaction.transaction_bytes(),
            Self::Recovery(transaction) => transaction.transaction_bytes(),
        }
    }

    const fn recipient(self) -> &'a Address {
        match self {
            Self::Fulfillment(transaction) => transaction.recipient(),
            Self::Recovery(transaction) => transaction.recipient(),
        }
    }
}

pub fn prepare_seller_recovery(
    supplied_lock: &SuppliedShakedexLock,
    recovery_recipient: Address,
    funding_inputs: Vec<Input>,
    funding_input_coins: Vec<Coin>,
    funding_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<PreparedSellerRecovery, ShakedexError> {
    validate_funding_suffix(
        &funding_inputs,
        &funding_input_coins,
        supplied_lock.locking_coin(),
    )?;
    validate_funding_outputs(&funding_outputs)?;
    let transaction = supplied_lock
        .descriptor()
        .recovery_transaction(
            supplied_lock.locking_coin(),
            &recovery_recipient,
            funding_inputs,
            funding_outputs,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    verify_recovery_structure(
        supplied_lock,
        &recovery_recipient,
        &funding_input_coins,
        expected_fee_base_units,
        &transaction,
        false,
    )?;
    let recovery_signature_hash = supplied_lock
        .descriptor()
        .recovery_signature_hash(
            &transaction,
            supplied_lock.locking_coin(),
            &recovery_recipient,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    Ok(PreparedSellerRecovery {
        supplied_lock: supplied_lock.clone(),
        recovery_recipient,
        funding_input_coins,
        unsigned_transaction: transaction,
        recovery_signature_hash,
        fee_base_units: expected_fee_base_units,
    })
}

/// Build seller recovery only from a freshly authenticated current lock. The
/// returned digest still requires the allocation-bound HNS Shakedex signer.
pub fn prepare_current_seller_recovery(
    current_lock: &VerifiedCurrentShakedexLock,
    recovery_recipient: Address,
    funding_inputs: Vec<Input>,
    funding_input_coins: Vec<Coin>,
    funding_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<CurrentPreparedSellerRecovery, ShakedexError> {
    let supplied_lock = supplied_lock_from_current(current_lock)?;
    let inner = prepare_seller_recovery(
        &supplied_lock,
        recovery_recipient,
        funding_inputs,
        funding_input_coins,
        funding_outputs,
        expected_fee_base_units,
    )?;
    Ok(CurrentPreparedSellerRecovery { inner })
}

pub fn verify_signed_seller_recovery(
    supplied_lock: &SuppliedShakedexLock,
    expected_recipient: &Address,
    funding_input_coins: &[Coin],
    expected_fee_base_units: u64,
    signed_transaction: &[u8],
) -> Result<VerifiedSellerRecovery, ShakedexError> {
    let transaction = decode_canonical_transaction(signed_transaction)?;
    verify_recovery_structure(
        supplied_lock,
        expected_recipient,
        funding_input_coins,
        expected_fee_base_units,
        &transaction,
        true,
    )?;
    Ok(VerifiedSellerRecovery {
        transaction: wallet_transaction_hash(&transaction)?,
        transaction_bytes: signed_transaction.to_vec(),
        recipient: expected_recipient.clone(),
        fee_base_units: expected_fee_base_units,
    })
}

/// Script-authorized FINALIZE awaiting only ordinary fee-input signatures.
pub struct PreparedScriptFinalize {
    supplied_lock: SuppliedShakedexLock,
    parent_transaction: TransactionHash,
    parent_transaction_bytes: Vec<u8>,
    parent_recipient: Address,
    transfer_coin: Coin,
    current_state: NameState,
    renewal_block: BlockHash,
    expected_recipient: Address,
    funding_input_coins: Vec<Coin>,
    prepared_transaction: Vec<u8>,
    fee_base_units: u64,
}

impl PreparedScriptFinalize {
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.prepared_transaction
    }

    pub fn funding_input_coins(&self) -> &[Coin] {
        &self.funding_input_coins
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }

    pub fn verify_signed(
        &self,
        signed_transaction: &[u8],
    ) -> Result<VerifiedScriptFinalize, ShakedexError> {
        require_witness_only_suffix_change(&self.prepared_transaction, signed_transaction)?;
        verify_signed_script_finalize_with_parent(
            &self.supplied_lock,
            self.parent_transaction,
            &self.parent_transaction_bytes,
            &self.parent_recipient,
            &self.transfer_coin,
            &self.current_state,
            self.renewal_block,
            &self.expected_recipient,
            &self.funding_input_coins,
            self.fee_base_units,
            signed_transaction,
        )
    }
}

pub struct VerifiedScriptFinalize {
    transaction: TransactionHash,
    transaction_bytes: Vec<u8>,
    recipient: Address,
    fee_base_units: u64,
}

impl VerifiedScriptFinalize {
    pub const fn transaction(&self) -> TransactionHash {
        self.transaction
    }

    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }

    pub const fn recipient(&self) -> &Address {
        &self.recipient
    }

    pub const fn fee_base_units(&self) -> u64 {
        self.fee_base_units
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_script_finalize(
    supplied_lock: &SuppliedShakedexLock,
    verified_parent: VerifiedShakedexTransfer<'_>,
    transfer_coin: Coin,
    supplied_current_state: NameState,
    supplied_renewal_block: BlockHash,
    expected_recipient: Address,
    funding_inputs: Vec<Input>,
    funding_input_coins: Vec<Coin>,
    funding_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<PreparedScriptFinalize, ShakedexError> {
    let parent_transaction = verified_parent.transaction();
    let parent_transaction_bytes = verified_parent.transaction_bytes();
    let parent_recipient = verified_parent.recipient();
    validate_funding_suffix(&funding_inputs, &funding_input_coins, &transfer_coin)?;
    validate_funding_outputs(&funding_outputs)?;
    verify_parent_transfer(
        supplied_lock,
        parent_transaction,
        parent_transaction_bytes,
        parent_recipient,
        &transfer_coin,
        &expected_recipient,
    )?;
    let mut transaction = build_finalize_transaction(
        &transfer_coin,
        &supplied_current_state,
        supplied_renewal_block,
        funding_inputs,
        funding_outputs,
    )
    .map_err(|_| ShakedexError::InvalidEvidence)?;
    transaction.inputs[0].witness = supplied_lock
        .descriptor()
        .finalize_witness()
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    verify_script_finalize_structure(
        supplied_lock,
        parent_transaction,
        parent_transaction_bytes,
        parent_recipient,
        &transfer_coin,
        &supplied_current_state,
        supplied_renewal_block,
        &expected_recipient,
        &funding_input_coins,
        expected_fee_base_units,
        &transaction,
        false,
    )?;
    Ok(PreparedScriptFinalize {
        supplied_lock: supplied_lock.clone(),
        parent_transaction,
        parent_transaction_bytes: parent_transaction_bytes.to_vec(),
        parent_recipient: parent_recipient.clone(),
        transfer_coin,
        current_state: supplied_current_state,
        renewal_block: supplied_renewal_block,
        expected_recipient,
        funding_input_coins,
        prepared_transaction: canonical_transaction_bytes(&transaction)?,
        fee_base_units: expected_fee_base_units,
    })
}

/// Build script-controlled FINALIZE from the HNS runtime's exact active-chain
/// TRANSFER, maturity, renewal-block, and unspent authority. The verified
/// parent must be byte-identical to that current owner transaction.
#[allow(clippy::too_many_arguments)]
pub fn prepare_current_script_finalize(
    supplied_lock: &SuppliedShakedexLock,
    verified_parent: VerifiedShakedexTransfer<'_>,
    current_transfer: &VerifiedCurrentShakedexTransfer,
    expected_recipient: Address,
    funding_inputs: Vec<Input>,
    funding_input_coins: Vec<Coin>,
    funding_outputs: Vec<Output>,
    expected_fee_base_units: u64,
) -> Result<PreparedScriptFinalize, ShakedexError> {
    if supplied_lock.descriptor() != current_transfer.descriptor()
        || verified_parent.transaction_bytes()
            != canonical_transaction_bytes(current_transfer.transfer_transaction())?
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    prepare_script_finalize(
        supplied_lock,
        verified_parent,
        current_transfer.transfer_coin().clone(),
        current_transfer.current_name_state().clone(),
        BlockHash::new(current_transfer.renewal_block_hash()),
        expected_recipient,
        funding_inputs,
        funding_input_coins,
        funding_outputs,
        expected_fee_base_units,
    )
}

/// Reauthenticate a signed script-controlled FINALIZE from complete supplied
/// structural evidence. Current chain state, transfer maturity, fee policy,
/// and unspentness remain runtime responsibilities.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_script_finalize(
    supplied_lock: &SuppliedShakedexLock,
    verified_parent: VerifiedShakedexTransfer<'_>,
    transfer_coin: &Coin,
    supplied_current_state: &NameState,
    supplied_renewal_block: BlockHash,
    expected_recipient: &Address,
    funding_input_coins: &[Coin],
    expected_fee_base_units: u64,
    signed_transaction: &[u8],
) -> Result<VerifiedScriptFinalize, ShakedexError> {
    verify_signed_script_finalize_with_parent(
        supplied_lock,
        verified_parent.transaction(),
        verified_parent.transaction_bytes(),
        verified_parent.recipient(),
        transfer_coin,
        supplied_current_state,
        supplied_renewal_block,
        expected_recipient,
        funding_input_coins,
        expected_fee_base_units,
        signed_transaction,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_signed_script_finalize_with_parent(
    supplied_lock: &SuppliedShakedexLock,
    parent_transaction: TransactionHash,
    parent_transaction_bytes: &[u8],
    parent_recipient: &Address,
    transfer_coin: &Coin,
    supplied_current_state: &NameState,
    supplied_renewal_block: BlockHash,
    expected_recipient: &Address,
    funding_input_coins: &[Coin],
    expected_fee_base_units: u64,
    signed_transaction: &[u8],
) -> Result<VerifiedScriptFinalize, ShakedexError> {
    let transaction = decode_canonical_transaction(signed_transaction)?;
    verify_script_finalize_structure(
        supplied_lock,
        parent_transaction,
        parent_transaction_bytes,
        parent_recipient,
        transfer_coin,
        supplied_current_state,
        supplied_renewal_block,
        expected_recipient,
        funding_input_coins,
        expected_fee_base_units,
        &transaction,
        true,
    )?;
    Ok(VerifiedScriptFinalize {
        transaction: wallet_transaction_hash(&transaction)?,
        transaction_bytes: signed_transaction.to_vec(),
        recipient: expected_recipient.clone(),
        fee_base_units: expected_fee_base_units,
    })
}

fn bind_listing_to_lock(
    listing: &AuthenticatedFixedPriceListing,
    supplied_lock: &SuppliedShakedexLock,
) -> Result<(), ShakedexError> {
    if listing.network() != supplied_lock.network()
        || listing.seller_public_key() != &supplied_lock.descriptor().seller_public_key
        || listing.locking_outpoint() != supplied_lock.locking_coin().outpoint
        || listing.name() != supplied_lock.descriptor().name
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    listing
        .proof()
        .verify_for_network(supplied_lock.network(), supplied_lock.locking_coin())
        .map_err(|_| ShakedexError::InvalidEvidence)
}

fn verify_fulfillment_structure(
    listing: &AuthenticatedFixedPriceListing,
    supplied_lock: &SuppliedShakedexLock,
    expected_recipient: &Address,
    buyer_input_coins: &[Coin],
    expected_fee_base_units: u64,
    transaction: &Transaction,
    verify_witnesses: bool,
) -> Result<(), ShakedexError> {
    bind_listing_to_lock(listing, supplied_lock)?;
    validate_resolved_funding_coins(transaction, buyer_input_coins, supplied_lock.locking_coin())?;
    listing
        .proof()
        .verify_fulfillment(transaction, supplied_lock.locking_coin())
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    if transaction.outputs.first()
        != Some(
            &build_transfer_output(supplied_lock.locking_coin(), expected_recipient)
                .map_err(|_| ShakedexError::InvalidEvidence)?,
        )
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let funding_output_start = 1_usize
        .checked_add(usize::from(listing.proof().fee.get() > 0))
        .ok_or(ShakedexError::InvalidEvidence)?;
    let funding_output_end = transaction
        .outputs
        .len()
        .checked_sub(1)
        .ok_or(ShakedexError::InvalidEvidence)?;
    validate_funding_outputs(
        transaction
            .outputs
            .get(funding_output_start..funding_output_end)
            .ok_or(ShakedexError::InvalidEvidence)?,
    )?;
    let coins = ordered_coins(supplied_lock.locking_coin(), buyer_input_coins)?;
    verify_transaction_accounting(transaction, &coins, expected_fee_base_units)?;
    if verify_witnesses {
        verify_all_witnesses(transaction, &coins)?;
    }
    Ok(())
}

fn verify_recovery_structure(
    supplied_lock: &SuppliedShakedexLock,
    expected_recipient: &Address,
    funding_input_coins: &[Coin],
    expected_fee_base_units: u64,
    transaction: &Transaction,
    verify_witnesses: bool,
) -> Result<(), ShakedexError> {
    validate_resolved_funding_coins(
        transaction,
        funding_input_coins,
        supplied_lock.locking_coin(),
    )?;
    if verify_witnesses {
        supplied_lock
            .descriptor()
            .verify_recovery(
                transaction,
                supplied_lock.locking_coin(),
                expected_recipient,
            )
            .map_err(|_| ShakedexError::InvalidEvidence)?;
    } else {
        supplied_lock
            .descriptor()
            .recovery_signature_hash(
                transaction,
                supplied_lock.locking_coin(),
                expected_recipient,
            )
            .map_err(|_| ShakedexError::InvalidEvidence)?;
    }
    validate_funding_outputs(
        transaction
            .outputs
            .get(1..)
            .ok_or(ShakedexError::InvalidEvidence)?,
    )?;
    let coins = ordered_coins(supplied_lock.locking_coin(), funding_input_coins)?;
    verify_transaction_accounting(transaction, &coins, expected_fee_base_units)?;
    if verify_witnesses {
        verify_all_witnesses(transaction, &coins)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_script_finalize_structure(
    supplied_lock: &SuppliedShakedexLock,
    parent_transaction: TransactionHash,
    parent_transaction_bytes: &[u8],
    parent_recipient: &Address,
    transfer_coin: &Coin,
    current_state: &NameState,
    renewal_block: BlockHash,
    expected_recipient: &Address,
    funding_input_coins: &[Coin],
    expected_fee_base_units: u64,
    transaction: &Transaction,
    verify_witnesses: bool,
) -> Result<(), ShakedexError> {
    verify_parent_transfer(
        supplied_lock,
        parent_transaction,
        parent_transaction_bytes,
        parent_recipient,
        transfer_coin,
        expected_recipient,
    )?;
    verify_transfer_binding(
        supplied_lock,
        transfer_coin,
        current_state,
        expected_recipient,
    )?;
    validate_resolved_funding_coins(transaction, funding_input_coins, transfer_coin)?;
    verify_finalize_at_index_zero(transaction, transfer_coin, current_state, renewal_block)
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    if transaction.inputs[0].witness
        != supplied_lock
            .descriptor()
            .finalize_witness()
            .map_err(|_| ShakedexError::InvalidEvidence)?
        || transaction.outputs.first().map(|output| &output.address) != Some(expected_recipient)
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    validate_funding_outputs(
        transaction
            .outputs
            .get(1..)
            .ok_or(ShakedexError::InvalidEvidence)?,
    )?;
    let coins = ordered_coins(transfer_coin, funding_input_coins)?;
    verify_transaction_accounting(transaction, &coins, expected_fee_base_units)?;
    if verify_witnesses {
        verify_all_witnesses(transaction, &coins)?;
    }
    Ok(())
}

fn verify_parent_transfer(
    supplied_lock: &SuppliedShakedexLock,
    parent_transaction: TransactionHash,
    parent_transaction_bytes: &[u8],
    parent_recipient: &Address,
    transfer_coin: &Coin,
    expected_recipient: &Address,
) -> Result<(), ShakedexError> {
    let parent = decode_canonical_transaction(parent_transaction_bytes)?;
    let parent_output = parent
        .outputs
        .first()
        .ok_or(ShakedexError::InvalidEvidence)?;
    if wallet_transaction_hash(&parent)? != parent_transaction
        || parent_recipient != expected_recipient
        || parent.inputs.first().map(|input| input.previous_output)
            != Some(supplied_lock.locking_coin().outpoint)
        || transfer_coin.outpoint.transaction_hash.as_bytes() != parent_transaction.as_bytes()
        || transfer_coin.outpoint.index != 0
        || transfer_coin.value != parent_output.value
        || transfer_coin.address != parent_output.address
        || transfer_coin.covenant != parent_output.covenant
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn verify_transfer_binding(
    supplied_lock: &SuppliedShakedexLock,
    transfer_coin: &Coin,
    current_state: &NameState,
    expected_recipient: &Address,
) -> Result<(), ShakedexError> {
    supplied_lock
        .descriptor()
        .verify_for_network(supplied_lock.network(), supplied_lock.locking_coin())
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    if transfer_coin.outpoint.is_null()
        || transfer_coin.coinbase
        || transfer_coin.address != supplied_lock.locking_coin().address
        || transfer_coin.value != supplied_lock.locking_coin().value
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    let original = FinalizeCovenant::try_from(&supplied_lock.locking_coin().covenant)
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    let transfer = TransferCovenant::try_from(&transfer_coin.covenant)
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    if transfer.name_hash != original.name_hash
        || transfer.start_height != original.start_height
        || transfer.recipient_version != expected_recipient.version
        || transfer.recipient_hash != expected_recipient.hash
        || current_state.name_hash != original.name_hash
        || current_state.name != original.name
        || current_state.height != original.start_height
        || current_state.owner != transfer_coin.outpoint
        || current_state.value != transfer_coin.value
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn validate_funding_suffix(
    inputs: &[Input],
    coins: &[Coin],
    primary_coin: &Coin,
) -> Result<(), ShakedexError> {
    if inputs.is_empty()
        || inputs.len() != coins.len()
        || inputs.len() > MAX_SHAKEDEX_FUNDING_INPUTS
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    for (input, coin) in inputs.iter().zip(coins) {
        if input.previous_output != coin.outpoint
            || coin.outpoint.is_null()
            || coin.outpoint == primary_coin.outpoint
            || coin.coinbase
            || coin.value.get() == 0
            || coin.covenant.kind != CovenantKind::None
            || coin.address.version != 0
            || coin.address.hash.len() != 20
            || !input.witness.items.is_empty()
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        coin.address
            .validate()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
    }
    if coins
        .iter()
        .map(|coin| coin.outpoint)
        .collect::<std::collections::HashSet<_>>()
        .len()
        != coins.len()
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn validate_funding_outputs(outputs: &[Output]) -> Result<(), ShakedexError> {
    if outputs.len() > MAX_SHAKEDEX_FUNDING_INPUTS {
        return Err(ShakedexError::InvalidEvidence);
    }
    for output in outputs {
        if output.value.get() == 0
            || output.covenant.kind != CovenantKind::None
            || output.address.version != 0
            || output.address.hash.len() != 20
        {
            return Err(ShakedexError::InvalidEvidence);
        }
        output
            .address
            .validate()
            .map_err(|_| ShakedexError::InvalidEvidence)?;
    }
    Ok(())
}

fn validate_resolved_funding_coins(
    transaction: &Transaction,
    funding_coins: &[Coin],
    primary_coin: &Coin,
) -> Result<(), ShakedexError> {
    if transaction.inputs.len() != funding_coins.len().saturating_add(1) {
        return Err(ShakedexError::InvalidEvidence);
    }
    let inputs = &transaction.inputs[1..];
    let mut unsigned_inputs = inputs.to_vec();
    for input in &mut unsigned_inputs {
        input.witness = Witness::default();
    }
    validate_funding_suffix(&unsigned_inputs, funding_coins, primary_coin)
}

fn ordered_coins(primary: &Coin, funding: &[Coin]) -> Result<Vec<Coin>, ShakedexError> {
    let mut coins = Vec::new();
    coins
        .try_reserve_exact(funding.len().saturating_add(1))
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    coins.push(primary.clone());
    coins.extend_from_slice(funding);
    Ok(coins)
}

fn verify_transaction_accounting(
    transaction: &Transaction,
    input_coins: &[Coin],
    expected_fee_base_units: u64,
) -> Result<(), ShakedexError> {
    if expected_fee_base_units == 0 {
        return Err(ShakedexError::InvalidEvidence);
    }
    verify_covenant_links(transaction, input_coins).map_err(|_| ShakedexError::InvalidEvidence)?;
    let input_total = input_coins.iter().try_fold(0_u128, |total, coin| {
        total.checked_add(u128::from(coin.value.get()))
    });
    let output_total = transaction
        .outputs
        .iter()
        .try_fold(0_u128, |total, output| {
            total.checked_add(u128::from(output.value.get()))
        });
    let fee = input_total
        .and_then(|input| output_total.and_then(|output| input.checked_sub(output)))
        .and_then(|fee| u64::try_from(fee).ok())
        .ok_or(ShakedexError::InvalidEvidence)?;
    if fee != expected_fee_base_units {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn verify_all_witnesses(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<(), ShakedexError> {
    for (index, coin) in input_coins.iter().enumerate() {
        if index > 0 {
            let [signature, public_key] = transaction
                .inputs
                .get(index)
                .ok_or(ShakedexError::InvalidEvidence)?
                .witness
                .items
                .as_slice()
            else {
                return Err(ShakedexError::InvalidEvidence);
            };
            if signature.len() != 65 || signature[64] != SIGHASH_ALL as u8 || public_key.len() != 33
            {
                return Err(ShakedexError::InvalidEvidence);
            }
        }
        verify_witness_program(
            transaction,
            index,
            coin,
            ScriptFlags::STANDARD,
            &K256SignatureVerifier,
        )
        .map_err(|_| ShakedexError::InvalidEvidence)?;
    }
    Ok(())
}

fn require_witness_only_suffix_change(prepared: &[u8], signed: &[u8]) -> Result<(), ShakedexError> {
    let prepared = decode_canonical_transaction(prepared)?;
    let signed = decode_canonical_transaction(signed)?;
    if prepared.version != signed.version
        || prepared.locktime != signed.locktime
        || prepared.outputs != signed.outputs
        || prepared.inputs.len() != signed.inputs.len()
        || prepared.inputs.first().map(|input| &input.witness)
            != signed.inputs.first().map(|input| &input.witness)
        || prepared
            .inputs
            .iter()
            .zip(&signed.inputs)
            .any(|(left, right)| {
                left.previous_output != right.previous_output || left.sequence != right.sequence
            })
    {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(())
}

fn decode_canonical_transaction(encoded: &[u8]) -> Result<Transaction, ShakedexError> {
    let transaction = Transaction::decode(encoded).map_err(|_| ShakedexError::InvalidEvidence)?;
    if canonical_transaction_bytes(&transaction)? != encoded {
        return Err(ShakedexError::InvalidEvidence);
    }
    Ok(transaction)
}

fn canonical_transaction_bytes(transaction: &Transaction) -> Result<Vec<u8>, ShakedexError> {
    transaction
        .encode()
        .map_err(|_| ShakedexError::InvalidEvidence)
}

fn wallet_transaction_hash(transaction: &Transaction) -> Result<TransactionHash, ShakedexError> {
    transaction
        .transaction_hash()
        .map(|hash| TransactionHash::new(hash.into_bytes()))
        .map_err(|_| ShakedexError::InvalidEvidence)
}
