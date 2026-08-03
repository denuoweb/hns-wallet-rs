#![doc = "Handshake wallet key roles, restoration, UTXO selection, and name workflows."]
#![forbid(unsafe_code)]

mod node_rpc;

pub use node_rpc::{HnsNodeRpcBackend, HnsNodeRpcConfig};

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bech32::{Hrp, segwit};
use bip39::{Language, Mnemonic};
use blake2::Blake2bVar;
use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use hkdf::Hkdf;
use hns_covenants::{Covenant, hash_name, validate_name};
use hns_primitives::{
    Dollarydoos, NameHash, TransactionHash as CanonicalTransactionHash, TreeRoot,
};
use hns_script::{
    OP_BLAKE160, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF,
    OP_EQUALVERIFY, OP_IF, OP_SHA256, SIGHASH_ALL, signature_hash,
};
use hns_transaction::{Address, Input, Outpoint, Output, Transaction, Witness};
use hns_urkel_proof::{ProofKind, UrkelProof};
use hns_wallet_chain_api::{
    AtomicSettlement, AuthorizeSend, AuthorizedSend, BroadcastReceipt, BroadcastSend, ChainError,
    ChainModule, HtlcLockRequest, HtlcRedeemRequest, HtlcRefundRequest, ModuleRegistry,
    ObservePreimageRequest, ObserveSecretRequest, Preimage, PreparedArtifact, PreparedHtlcLock,
    PreparedHtlcRedeem, PreparedHtlcRefund, PreparedSend, PreparedSettlementLock,
    PreparedSettlementRedeem, PreparedSettlementRefund, RegistryError, SendRequest,
    SettlementCapabilities, SettlementLockExpectation, SettlementLockRequest,
    SettlementRedeemRequest, SettlementRefundRequest, Utxo, UtxoChainModule, UtxoFeePolicy,
    VerifiedHtlcLock, VerifiedLock, VerifiedSettlementLock, VerifyHtlcLockRequest,
    VerifySettlementLockRequest,
};
use hns_wallet_store::{
    EntityBatchDelete, EntityBatchSave, EntityKind, SecretKind, StoreError, StoredEntity,
    WalletStore,
};
use hns_wallet_types::{
    AccountId, Amount, ApprovalId, BaseUnits, ChainCapabilities, DerivationReference, FeeModel,
    FinalityModel, HashAlgorithm, KeyRole, LocalTransactionStatus, LocktimeModel, ModuleId,
    ObjectHash, ReceiveTarget, SessionId, SignedBaseUnits, SyncPhase, SyncStatus, TransactionHash,
    TransactionSummary, WalletAsset, WalletId, WorkflowId, WorkflowKind,
};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HNS_DERIVATION_DOMAIN: &[u8] = b"hns-wallet-rs/hns-role-key/v1";
pub const HNS_SETTLEMENT_KEY_DOMAIN: &[u8] = b"hns-wallet-rs/hns-settlement-key/v1";
pub const MAX_RESTORE_LOOKAHEAD: u32 = 10_000;
pub const MAX_RESTORE_SCRIPTS_PER_QUERY: usize = 10_000;
/// The coin and dedicated name branches are queried separately so neither
/// branch reduces the other's bounded lookahead. Persisted address records
/// are nevertheless bounded as one account-owned collection.
pub const MAX_RESTORE_ADDRESS_RECORDS: usize = MAX_RESTORE_SCRIPTS_PER_QUERY * 2;
pub const DEFAULT_RESTORE_LOOKAHEAD: u32 = 100;
pub const MAX_WALLET_COINS: usize = 10_000;
pub const MAX_HISTORY_RESULTS: usize = 10_000;
pub const MAX_RECOVERY_CHECKPOINTS: usize = 288;
pub const MAX_TRANSACTION_INPUTS: usize = 10_000;
pub const PREPARED_ARTIFACT_LIFETIME_SECONDS: u64 = 300;
pub const DEFAULT_DUST_THRESHOLD: u128 = 546;
pub const HNS_LOCKTIME_THRESHOLD: u64 = 500_000_000;
pub const MAX_SCAN_PAGE_RESULTS: usize = 256;
pub const MAX_MEMPOOL_SCAN_RESULTS: usize = 1_024;
pub const MAX_OUTPOINT_SPEND_BATCH: usize = 256;
pub const MAX_SCAN_CURSOR_BYTES: usize = 4_096;
pub const MAX_SCAN_PAGES: usize = 128;
pub const MAX_SNAPSHOT_RESTARTS: usize = 3;
pub const DEFAULT_FEE_TARGET_BLOCKS: u16 = 6;
/// The wallet is still pinned to released hns-script 0.1, which does not
/// expose canonical HSD fee-policy algebra. Exact node quotes are adopted and
/// persisted, but cannot authorize value until the released 0.2 helper is
/// consumed without duplicating node policy in this crate.
pub const HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED: bool = false;
/// Release gate: value operations stay unavailable until the concrete node
/// adapter and the complete runtime qualification suite pass together.
pub const HNS_VALUE_RUNTIME_RELEASE_QUALIFIED: bool = false;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HnsNetwork {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl HnsNetwork {
    const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "hs",
            Self::Testnet => "ts",
            Self::Regtest => "rs",
            Self::Simnet => "ss",
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase(String);

impl RecoveryPhrase {
    /// Dedicated high-risk display boundary. Provider and ordinary FFI
    /// operations must never call this method.
    pub fn expose_for_dedicated_display(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryPhrase([REDACTED])")
    }
}

#[derive(Debug)]
pub struct CreatedWallet {
    pub wallet_id: WalletId,
    pub recovery_phrase: RecoveryPhrase,
}

pub fn create_wallet(
    store: &mut WalletStore,
    now_unix: u64,
) -> Result<CreatedWallet, HnsWalletError> {
    let mnemonic =
        Mnemonic::generate_in(Language::English, 24).map_err(|_| HnsWalletError::Randomness)?;
    let mut wallet_id = [0_u8; 16];
    getrandom::fill(&mut wallet_id).map_err(|_| HnsWalletError::Randomness)?;
    let wallet_id = WalletId::new(wallet_id);
    store_seed(store, wallet_id, &mnemonic, now_unix)?;
    Ok(CreatedWallet {
        wallet_id,
        recovery_phrase: RecoveryPhrase(mnemonic.to_string()),
    })
}

pub fn restore_wallet(
    store: &mut WalletStore,
    phrase: &str,
    now_unix: u64,
) -> Result<WalletId, HnsWalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| HnsWalletError::InvalidRecoveryPhrase)?;
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-id/v1");
    hasher.update(mnemonic.to_seed_normalized(""));
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    let wallet_id = WalletId::new(id);
    store_seed(store, wallet_id, &mnemonic, now_unix)?;
    Ok(wallet_id)
}

fn store_seed(
    store: &mut WalletStore,
    wallet_id: WalletId,
    mnemonic: &Mnemonic,
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    store.put_secret(
        wallet_id.as_bytes(),
        SecretKind::RecoverySeed,
        seed.as_slice(),
        now_unix,
    )?;
    Ok(())
}

pub fn derive_hns_public_key(
    store: &WalletStore,
    wallet_id: WalletId,
    reference: DerivationReference,
) -> Result<[u8; 33], HnsWalletError> {
    if !matches!(
        reference.role,
        KeyRole::HnsCoin
            | KeyRole::HnsName
            | KeyRole::HnsShakedex
            | KeyRole::HnsAtomicSwap
            | KeyRole::HnsIdentity
            | KeyRole::HnsDappSession
    ) {
        return Err(HnsWalletError::WrongKeyRole);
    }
    let seed = store
        .get_secret(wallet_id.as_bytes(), SecretKind::RecoverySeed)?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_secret(&seed, reference)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    let encoded = VerifyingKey::from(&signing).to_encoded_point(true);
    encoded
        .as_bytes()
        .try_into()
        .map_err(|_| HnsWalletError::KeyDerivation)
}

fn derive_secret(
    seed: &[u8],
    reference: DerivationReference,
) -> Result<Zeroizing<[u8; 32]>, HnsWalletError> {
    let role = key_role_code(reference.role).ok_or(HnsWalletError::WrongKeyRole)?;
    for counter in 0_u8..=u8::MAX {
        let mut info = Vec::with_capacity(HNS_DERIVATION_DOMAIN.len() + 18);
        info.extend_from_slice(HNS_DERIVATION_DOMAIN);
        info.extend_from_slice(&role.to_be_bytes());
        info.extend_from_slice(&reference.account.to_be_bytes());
        info.extend_from_slice(&reference.change.to_be_bytes());
        info.extend_from_slice(&reference.index.to_be_bytes());
        info.push(counter);
        let hkdf = Hkdf::<Sha256>::new(Some(b"Handshake role separation"), seed);
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if SigningKey::from_slice(candidate.as_slice()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(HnsWalletError::KeyDerivation)
}

const fn key_role_code(role: KeyRole) -> Option<u32> {
    match role {
        KeyRole::HnsCoin => Some(0),
        KeyRole::HnsName => Some(1),
        KeyRole::HnsShakedex => Some(2),
        KeyRole::HnsAtomicSwap => Some(3),
        KeyRole::HnsIdentity => Some(4),
        KeyRole::HnsDappSession => Some(5),
        _ => None,
    }
}

pub fn receive_address(
    network: HnsNetwork,
    compressed_public_key: &[u8; 33],
) -> Result<String, HnsWalletError> {
    let program = public_key_hash(compressed_public_key)?;
    let hrp = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::Address)?;
    segwit::encode_v0(hrp, &program).map_err(|_| HnsWalletError::Address)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletCoin {
    pub outpoint: HnsOutpoint,
    pub value: BaseUnits,
    pub confirmation_count: u32,
    /// Exact node evidence. Coinbase outputs remain conservatively excluded
    /// until a released canonical maturity policy is wired into selection.
    #[serde(default = "coinbase_evidence_unknown")]
    pub coinbase: bool,
    pub name_locked: bool,
}

const fn coinbase_evidence_unknown() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct HnsOutpoint {
    pub transaction: TransactionHash,
    pub output_index: u32,
}

pub fn select_coins(
    coins: &[WalletCoin],
    target: BaseUnits,
) -> Result<CoinSelection, HnsWalletError> {
    if target.is_zero() || coins.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    let mut candidates: Vec<_> = coins
        .iter()
        .filter(|coin| !coin.name_locked && !coin.coinbase)
        .cloned()
        .collect();
    candidates.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| left.outpoint.cmp(&right.outpoint))
    });
    let mut selected = Vec::new();
    let mut total = BaseUnits::ZERO;
    for coin in candidates {
        total = total
            .checked_add(coin.value)
            .map_err(|_| HnsWalletError::Arithmetic)?;
        selected.push(coin);
        if total >= target {
            let change = total
                .checked_sub(target)
                .map_err(|_| HnsWalletError::Arithmetic)?;
            return Ok(CoinSelection {
                coins: selected,
                total,
                change,
            });
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoinSelection {
    pub coins: Vec<WalletCoin>,
    pub total: BaseUnits,
    pub change: BaseUnits,
}

pub trait HnsBackend {
    fn get_chain_tip(&self) -> Result<ChainTip, HnsWalletError>;
    fn get_block_hash(
        &self,
        height: u64,
        binding: SnapshotBinding,
    ) -> Result<BlockHashEvidence, HnsWalletError>;
    /// Pages confirmed history and UTXOs over the complete sorted script set.
    /// The adapter must reject a stale epoch/cursor with `StaleNodeSnapshot`.
    fn get_confirmed_wallet_page(
        &self,
        request: ConfirmedWalletPageRequest<'_>,
    ) -> Result<ConfirmedWalletPage, HnsWalletError>;
    /// Pages mempool history at one node-instance/generation pair, also tied
    /// to the confirmed chain binding and exact script set. The adapter must
    /// reject a stale instance, generation, script set, or cursor.
    fn get_mempool_wallet_page(
        &self,
        request: MempoolWalletPageRequest<'_>,
    ) -> Result<MempoolWalletPage, HnsWalletError>;
    /// Returns raw bytes, status, and inclusion from one canonical snapshot.
    /// A pruned node may omit raw bytes, but not the other fields.
    fn get_transaction_evidence(
        &self,
        txid: TransactionHash,
        binding: SnapshotBinding,
        expected_mempool: Option<MempoolSnapshotBinding>,
    ) -> Result<TransactionEvidence, HnsWalletError>;
    fn get_outpoint_spend_evidence(
        &self,
        outpoints: &[HnsOutpoint],
        binding: SnapshotBinding,
    ) -> Result<OutpointSpendEvidence, HnsWalletError>;
    fn broadcast_transaction(&self, raw: &[u8]) -> Result<TransactionHash, HnsWalletError>;
    /// Quotes one exact serialized transaction against the complete wallet
    /// reconciliation binding. Input values, sigops, policy size, and rate
    /// samples are node-resolved evidence; this method never signs or submits.
    fn quote_transaction_fee(
        &self,
        raw: &[u8],
        target_blocks: u16,
        binding: SnapshotBinding,
        expected_mempool: MempoolSnapshotBinding,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError>;
    /// Node estimate in atomic units per 1,000 HSD policy virtual bytes. The
    /// dormant wallet fee constructor is not release-qualified to apply this
    /// rate until canonical sigop-adjusted policy sizing is available.
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<BaseUnits, HnsWalletError>;
    /// Returns the interval-committed proof view and current name view without
    /// collapsing them. Every field is tied to the supplied snapshot binding.
    fn get_name_evidence(
        &self,
        name_hash: [u8; 32],
        binding: SnapshotBinding,
    ) -> Result<NameEvidence, HnsWalletError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tree_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotBinding {
    pub tip: ChainTip,
    /// Durable monotonic canonical-chain epoch owned by the node wallet index.
    pub chain_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockHashEvidence {
    pub binding: SnapshotBinding,
    pub height: u64,
    pub block_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub in_mempool: bool,
    pub confirmation_count: u32,
    pub conflicted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionInclusion {
    pub block_hash: [u8; 32],
    pub height: u64,
    /// Exact block transaction position when retained payload permits the node
    /// to derive it. A pruned payload must remain `None`, never invented zero.
    pub transaction_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub txid: TransactionHash,
    pub height: Option<u64>,
    pub block_hash: Option<[u8; 32]>,
    pub transaction_position: Option<u32>,
    pub spent: bool,
    /// Exact block time or mempool admission time. Confirmed header time may
    /// be unavailable and must remain `None`.
    pub first_seen_unix: Option<u64>,
    pub script_index: u32,
}

/// One backend UTXO tied to the index of the requested script. Returning the
/// index instead of wallet derivation data keeps the node boundary watch-only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedWalletCoin {
    pub coin: WalletCoin,
    pub script_index: u32,
    /// Canonical output address observed by the node. It must equal the exact
    /// requested version/hash pair, not merely its hash bytes.
    pub output_address: WalletAddressKey,
}

/// Exact canonical Handshake address input for the node's ScriptId conversion.
/// The current wallet derives version-0 public-key-hash addresses only.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct WalletAddressKey {
    pub version: u8,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedWalletPageRequest<'a> {
    pub scripts: &'a [WalletAddressKey],
    pub expected_tip: ChainTip,
    pub expected_epoch: Option<u64>,
    pub cursor: Option<&'a [u8]>,
    pub limit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfirmedWalletPage {
    pub binding: SnapshotBinding,
    pub next_cursor: Option<Vec<u8>>,
    pub history: Vec<HistoryEntry>,
    pub utxos: Vec<IndexedWalletCoin>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolWalletPageRequest<'a> {
    pub scripts: &'a [WalletAddressKey],
    pub binding: SnapshotBinding,
    /// The adapter must bind this instance/generation pair, the exact sorted
    /// script set, and the cursor into one page query.
    pub expected_mempool: Option<MempoolSnapshotBinding>,
    pub cursor: Option<&'a [u8]>,
    pub limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolSnapshotBinding {
    /// Nonpersistent node-process identity. It prevents a generation counter
    /// reset after restart from being mistaken for the prior mempool view.
    pub instance_nonce: [u8; 32],
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsFeeRateSource {
    MinimumRelay,
    Mempool,
}

/// Exact node-resolved HSD policy evidence for one serialized transaction.
/// The transaction bytes remain the durable source artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsTransactionFeeQuote {
    pub txid: TransactionHash,
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub target_blocks: u16,
    pub rate_atomic_units_per_1000_policy_vbytes: u64,
    pub rate_sample_count: usize,
    pub rate_source: HnsFeeRateSource,
    pub transaction_weight: usize,
    pub transaction_sigops: u32,
    pub sigop_adjusted_policy_vbytes: usize,
    pub minimum_policy_fee: BaseUnits,
    pub actual_fee: BaseUnits,
    pub meets_minimum_policy_fee: bool,
    pub minimum_policy_fee_shortfall: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolWalletPage {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub next_cursor: Option<Vec<u8>>,
    pub history: Vec<HistoryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionEvidence {
    pub binding: SnapshotBinding,
    pub mempool: MempoolSnapshotBinding,
    pub raw: Option<Vec<u8>>,
    pub status: TransactionStatus,
    pub inclusion: Option<TransactionInclusion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendEvidence {
    pub binding: SnapshotBinding,
    /// Exactly one echoed entry per requested outpoint, in request order.
    pub entries: Vec<OutpointSpendEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutpointSpendEntry {
    pub outpoint: HnsOutpoint,
    pub spending: Option<SpendingTransactionEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendingTransactionEvidence {
    pub transaction: TransactionHash,
    pub input_position: u32,
    pub block_hash: [u8; 32],
    pub height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameProofResponse {
    pub name_hash: [u8; 32],
    pub tree_root: [u8; 32],
    pub proof: Vec<u8>,
    pub proof_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameEvidence {
    pub binding: SnapshotBinding,
    pub proof: NameProofResponse,
    /// The interval-committed state bytes. These must exactly equal the bytes
    /// recovered by strict Urkel proof verification.
    pub proof_state: Option<Vec<u8>>,
    /// Node-decoded hint, not independently linked to `proof_state` until a
    /// released canonical NameState decoder is available.
    pub proof_owner_outpoint: Option<HnsOutpoint>,
    pub proof_owner_transaction: Option<Vec<u8>>,
    /// The node's current canonical view at `binding`. It may differ from the
    /// most recently committed name-tree proof view.
    pub current_state: Option<Vec<u8>>,
    /// Node-decoded hint, not independently linked to `current_state` yet.
    pub current_owner_outpoint: Option<HnsOutpoint>,
    pub current_owner_transaction: Option<Vec<u8>>,
    /// Resource bytes cannot yet be parsed from and bound to canonical name
    /// state by a released `hns-rs` API. Callers must not display these as
    /// proof-authenticated.
    pub untrusted_current_raw_resource: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameResourceStatus {
    UnavailableCanonicalBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOwnershipStatus {
    /// The released protocol crates cannot yet decode canonical NameState and
    /// bind its owner fields to the separately returned owner transaction.
    WatchOnlyCanonicalStateDecoderUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnownName {
    pub name: Vec<u8>,
    pub name_hash: [u8; 32],
    pub proof_height: u64,
    pub unbound_proof_owner_outpoint: Option<HnsOutpoint>,
    pub unbound_current_owner_outpoint: Option<HnsOutpoint>,
    pub proof_state: Option<Vec<u8>>,
    pub current_state: Option<Vec<u8>>,
    pub resource_status: NameResourceStatus,
    pub ownership_status: NameOwnershipStatus,
}

pub fn import_known_name<B: HnsBackend>(
    backend: &B,
    name: &[u8],
    binding: SnapshotBinding,
) -> Result<KnownName, HnsWalletError> {
    validated_name_evidence(backend, name, binding)
}

fn validated_name_evidence<B: HnsBackend>(
    backend: &B,
    name: &[u8],
    binding: SnapshotBinding,
) -> Result<KnownName, HnsWalletError> {
    if !validate_name(name) {
        return Err(HnsWalletError::InvalidName);
    }
    let name_hash = hash_name(name)
        .map_err(|_| HnsWalletError::InvalidName)?
        .into_bytes();
    let evidence = backend.get_name_evidence(name_hash, binding)?;
    if evidence.binding != binding {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    let response = &evidence.proof;
    if response.name_hash != name_hash
        || response.tree_root != binding.tip.tree_root
        || response.proof_height != binding.tip.height
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let proof = UrkelProof {
        name_hash: NameHash::new(name_hash),
        kind: if evidence.proof_state.is_some() {
            ProofKind::Inclusion
        } else {
            ProofKind::NonInclusion
        },
        raw: response.proof.clone(),
    };
    let proof_state = proof
        .verify_strict(TreeRoot::new(response.tree_root))
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if proof_state != evidence.proof_state
        || (evidence.proof_state.is_none() && evidence.proof_owner_outpoint.is_some())
        || (evidence.current_state.is_none() && evidence.current_owner_outpoint.is_some())
        || evidence.proof_owner_outpoint.is_some() != evidence.proof_owner_transaction.is_some()
        || evidence.current_owner_outpoint.is_some() != evidence.current_owner_transaction.is_some()
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    validate_name_owner_transaction(
        evidence.proof_owner_outpoint,
        evidence.proof_owner_transaction.as_deref(),
    )?;
    validate_name_owner_transaction(
        evidence.current_owner_outpoint,
        evidence.current_owner_transaction.as_deref(),
    )?;
    Ok(KnownName {
        name: name.to_vec(),
        name_hash,
        proof_height: response.proof_height,
        unbound_proof_owner_outpoint: evidence.proof_owner_outpoint,
        unbound_current_owner_outpoint: evidence.current_owner_outpoint,
        proof_state,
        current_state: evidence.current_state,
        resource_status: NameResourceStatus::UnavailableCanonicalBinding,
        ownership_status: NameOwnershipStatus::WatchOnlyCanonicalStateDecoderUnavailable,
    })
}

fn validate_name_owner_transaction(
    owner: Option<HnsOutpoint>,
    raw: Option<&[u8]>,
) -> Result<(), HnsWalletError> {
    match (owner, raw) {
        (None, None) => Ok(()),
        (Some(owner), Some(raw)) => {
            let transaction = decode_transaction_for_id(raw, owner.transaction)?;
            transaction
                .outputs
                .get(owner.output_index as usize)
                .ok_or(HnsWalletError::InvalidEvidence)?;
            Ok(())
        }
        _ => Err(HnsWalletError::InvalidEvidence),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOperationState {
    OwnershipVerified,
    Prepared,
    Broadcast,
    TransferLocked,
    FinalizeEligible,
    Finalized,
    Reorged,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameOperation {
    pub workflow_id: WorkflowId,
    pub revision: u64,
    pub name_hash: ObjectHash,
    pub state: NameOperationState,
    pub transaction: Option<TransactionHash>,
    pub transfer_height: Option<u64>,
    pub last_verified_height: u64,
}

impl NameOperation {
    pub fn persist(
        &mut self,
        store: &mut WalletStore,
        kind: WorkflowKind,
        irreversible_broadcast_prepared: bool,
        now_unix: u64,
    ) -> Result<(), HnsWalletError> {
        if !matches!(
            kind,
            WorkflowKind::NameTransfer | WorkflowKind::NameFinalize
        ) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let next = store.save_workflow(
            self.workflow_id,
            kind,
            self.revision,
            self,
            irreversible_broadcast_prepared,
            now_unix,
        )?;
        self.revision = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsRuntimeConfig {
    pub wallet_id: WalletId,
    pub account_id: AccountId,
    /// Stable HD account component. It is deliberately independent of the
    /// random wallet-local `AccountId` and must be backed up with the profile.
    pub account_derivation_index: u32,
    pub network: HnsNetwork,
    pub birthday_height: u64,
    pub restore_lookahead: u32,
    pub minimum_confirmations: u32,
    pub dust_threshold: BaseUnits,
    /// This is an application release-policy switch, not a test-network check.
    pub value_operations_enabled: bool,
    pub settlement_enabled: bool,
}

impl HnsRuntimeConfig {
    pub fn validate(&self) -> Result<(), HnsWalletError> {
        if self.restore_lookahead == 0
            || self.restore_lookahead > MAX_RESTORE_LOOKAHEAD
            || self.restore_lookahead as usize * 2 > MAX_RESTORE_SCRIPTS_PER_QUERY
        {
            return Err(HnsWalletError::InvalidLookahead);
        }
        if self.minimum_confirmations == 0 || self.dust_threshold.is_zero() {
            return Err(HnsWalletError::InvalidRuntimeConfiguration);
        }
        if self.network == HnsNetwork::Mainnet
            && (self.value_operations_enabled || self.settlement_enabled)
        {
            return Err(HnsWalletError::MainnetDisabled);
        }
        if (!HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
            || !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED)
            && (self.value_operations_enabled || self.settlement_enabled)
        {
            return Err(HnsWalletError::RuntimeIntegrationUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsAccountRecord {
    pub config: HnsRuntimeConfig,
    pub next_receive_index: u32,
    pub next_change_index: u32,
    /// Next dedicated name-key derivation. This is restoration metadata only;
    /// it does not establish ownership without canonical NameState evidence.
    #[serde(default)]
    pub next_name_index: u32,
    pub external_scan_end: u32,
    pub internal_scan_end: u32,
    /// Inclusive end of the independent `HnsName`, change-zero scan branch.
    #[serde(default)]
    pub name_scan_end: u32,
    pub last_used_external: Option<u32>,
    pub last_used_internal: Option<u32>,
    #[serde(default)]
    pub last_used_name: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivedHnsAddress {
    pub account_id: AccountId,
    pub derivation: DerivationReference,
    pub address: String,
    pub program: Vec<u8>,
    pub used: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrackedHnsCoin {
    pub coin: WalletCoin,
    pub derivation: DerivationReference,
    pub address_program: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsTransactionRecord {
    pub summary: TransactionSummary,
    pub raw: Vec<u8>,
    pub inclusion: Option<TransactionInclusion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsChainCheckpoint {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HnsRecoveryState {
    pub checkpoints: Vec<HnsChainCheckpoint>,
    pub last_tip: Option<ChainTip>,
    pub last_common_ancestor: Option<u64>,
    pub last_reconciled_unix: u64,
}

impl Default for HnsRecoveryState {
    fn default() -> Self {
        Self {
            checkpoints: Vec::new(),
            last_tip: None,
            last_common_ancestor: None,
            last_reconciled_unix: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsReconciliationReport {
    pub tip: ChainTip,
    pub common_ancestor: Option<u64>,
    pub reorg_detected: bool,
    pub restored_utxos: usize,
    pub reconciled_transactions: usize,
    pub revalidated_names: usize,
    pub pending_user_actions: Vec<WorkflowId>,
}

pub trait HnsClock: Send + Sync {
    fn now_unix(&self) -> Result<u64, HnsWalletError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl HnsClock for SystemClock {
    fn now_unix(&self) -> Result<u64, HnsWalletError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HnsWalletError::Clock)
            .map(|duration| duration.as_secs())
    }
}

#[derive(Clone, Debug)]
struct HnsRuntimeCache {
    account: HnsAccountRecord,
    account_revision: u64,
    sync: SyncStatus,
    coins: Vec<TrackedHnsCoin>,
    transactions: Vec<HnsTransactionRecord>,
    binding: Option<SnapshotBinding>,
    mempool_binding: Option<MempoolSnapshotBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HnsSendStage {
    Prepared,
    Authorized,
    Broadcast,
    Mempool,
    Confirmed,
    Conflicted,
    RequiresRebroadcast,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HnsSpendPlan {
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    request_nonce: u64,
    unsigned_transaction: Vec<u8>,
    inputs: Vec<TrackedHnsCoin>,
    amount: BaseUnits,
    fee: BaseUnits,
    maximum_fee: BaseUnits,
    destination: String,
    expires_at_unix: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct HnsSendWorkflow {
    plan: HnsSpendPlan,
    stage: HnsSendStage,
    transaction: Option<TransactionHash>,
    signed_transaction: Option<Vec<u8>>,
    #[serde(default)]
    fee_quote: Option<HnsTransactionFeeQuote>,
}

impl fmt::Debug for HnsSendWorkflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsSendWorkflow")
            .field("workflow_id", &self.plan.workflow_id)
            .field("stage", &self.stage)
            .field("transaction", &self.transaction)
            .field(
                "signed_transaction",
                &self.signed_transaction.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct HnsSendApproval {
    workflow_id: WorkflowId,
    commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HnsInputReservation {
    wallet_id: WalletId,
    account_id: AccountId,
    outpoint: HnsOutpoint,
    workflow_id: WorkflowId,
    expires_at_unix: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HnsSettlementAction {
    Lock,
    Redeem,
    Refund,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HnsSettlementStage {
    Prepared,
    Broadcast,
    Mempool,
    Confirmed,
    Conflicted,
    RequiresRebroadcast,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
enum HnsSettlementTerms {
    Lock { request: SettlementLockRequest },
    Redeem { lock: VerifiedLock },
    Refund { lock: VerifiedLock },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HnsVerifiedSettlementRecord {
    expected: SettlementLockExpectation,
    verified: VerifiedLock,
    output_index: u32,
    script: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct HnsPreparedSettlement {
    wallet_id: WalletId,
    account_id: AccountId,
    workflow_id: WorkflowId,
    session_id: SessionId,
    action: HnsSettlementAction,
    stage: HnsSettlementStage,
    transaction: TransactionHash,
    signed_transaction: Vec<u8>,
    fee: BaseUnits,
    #[serde(default)]
    maximum_fee: BaseUnits,
    #[serde(default)]
    fee_quote: Option<HnsTransactionFeeQuote>,
    expires_at_unix: u64,
    terms: HnsSettlementTerms,
}

impl fmt::Debug for HnsPreparedSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HnsPreparedSettlement")
            .field("workflow_id", &self.workflow_id)
            .field("session_id", &self.session_id)
            .field("action", &self.action)
            .field("stage", &self.stage)
            .field("transaction", &self.transaction)
            .field("fee", &self.fee)
            .field("maximum_fee", &self.maximum_fee)
            .field("fee_quote", &self.fee_quote)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("terms", &self.terms)
            .field("signed_transaction", &"[REDACTED]")
            .finish()
    }
}

pub struct HnsWalletRuntime<B, C = SystemClock> {
    backend: B,
    clock: C,
    store: Mutex<WalletStore>,
    cache: RwLock<HnsRuntimeCache>,
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    pub fn open(
        backend: B,
        mut store: WalletStore,
        config: HnsRuntimeConfig,
        clock: C,
    ) -> Result<Self, HnsWalletError> {
        config.validate()?;
        if store.is_locked() {
            return Err(HnsWalletError::StoreLocked);
        }
        if store
            .wallet_accounts::<HnsAccountRecord>(MAX_HISTORY_RESULTS)?
            .into_iter()
            .any(|stored| {
                stored.value.config.wallet_id == config.wallet_id
                    && stored.value.config.account_id != config.account_id
                    && stored.value.config.account_derivation_index
                        == config.account_derivation_index
            })
        {
            return Err(HnsWalletError::DuplicateAccountDerivation);
        }
        let existing: Option<StoredEntity<HnsAccountRecord>> =
            store.wallet_account(&account_entity_id(&config))?;
        let (account, account_revision) = match existing {
            Some(mut stored) => {
                if !same_account_identity(&stored.value.config, &config) {
                    return Err(HnsWalletError::AccountConfigurationMismatch);
                }
                if stored.value.config != config {
                    stored.value.config = config;
                    stored.revision = store.save_wallet_account(
                        &account_entity_id(&stored.value.config),
                        stored.revision,
                        &stored.value,
                        clock.now_unix()?,
                    )?;
                }
                (stored.value, stored.revision)
            }
            None => {
                let external_scan_end = config.restore_lookahead - 1;
                let account = HnsAccountRecord {
                    config,
                    next_receive_index: 0,
                    next_change_index: 0,
                    next_name_index: 0,
                    external_scan_end,
                    internal_scan_end: external_scan_end,
                    name_scan_end: external_scan_end,
                    last_used_external: None,
                    last_used_internal: None,
                    last_used_name: None,
                };
                let revision = store.save_wallet_account(
                    &account_entity_id(&account.config),
                    0,
                    &account,
                    clock.now_unix()?,
                )?;
                (account, revision)
            }
        };
        let coins = store
            .hns_utxos::<TrackedHnsCoin>(MAX_HISTORY_RESULTS)?
            .into_iter()
            .filter(|entity| {
                entity
                    .id
                    .starts_with(&account_entity_prefix(&account.config))
            })
            .map(|entity| entity.value)
            .collect();
        let transactions = store
            .hns_transactions::<HnsTransactionRecord>(MAX_HISTORY_RESULTS)?
            .into_iter()
            .filter(|entity| {
                entity
                    .id
                    .starts_with(&account_entity_prefix(&account.config))
            })
            .map(|entity| entity.value)
            .collect();
        Ok(Self {
            backend,
            clock,
            store: Mutex::new(store),
            cache: RwLock::new(HnsRuntimeCache {
                account,
                account_revision,
                sync: SyncStatus {
                    phase: SyncPhase::Starting,
                    validated_height: 0,
                    scanned_height: 0,
                    target_height: None,
                    last_error: None,
                },
                coins,
                transactions,
                binding: None,
                mempool_binding: None,
            }),
        })
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn register<'a>(&'a self, registry: &mut ModuleRegistry<'a>) -> Result<(), RegistryError> {
        registry.register_utxo_settlement(self)
    }

    /// Called only after the trusted approval UI has compared the complete
    /// prepared artifact. The stored commitment is encrypted and single-use.
    pub fn register_send_approval(
        &self,
        approval_id: ApprovalId,
        origin: &str,
        prepared: &PreparedSend,
        expires_at_unix: u64,
    ) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let plan: HnsSpendPlan = serde_json::from_slice(prepared.authorization_commitment())
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if prepared.module != ModuleId::Handshake
            || plan.expires_at_unix != prepared.expires_at_unix
            || plan.amount != prepared.amount.base_units
            || plan.fee != prepared.fee
            || plan.destination != prepared.destination
            || expires_at_unix > plan.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let approval = HnsSendApproval {
            workflow_id: plan.workflow_id,
            commitment: Sha256::digest(prepared.authorization_commitment()).into(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&approval)?);
        self.store_lock()?.put_pending_approval(
            approval_id,
            origin,
            &encoded,
            now,
            expires_at_unix,
        )?;
        Ok(())
    }

    pub fn rebroadcast_pending_send(
        &self,
        workflow_id: WorkflowId,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        let stored = self
            .store_lock()?
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if !matches!(
            stored.state.stage,
            HnsSendStage::Authorized
                | HnsSendStage::Broadcast
                | HnsSendStage::Mempool
                | HnsSendStage::RequiresRebroadcast
        ) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let raw = stored
            .state
            .signed_transaction
            .clone()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let expected = stored
            .state
            .transaction
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        let prior_quote = stored
            .state
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        validate_final_fee_quote(
            &raw,
            prior_quote,
            prior_quote.binding,
            prior_quote.mempool,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let quote = self.quote_final_transaction(
            &raw,
            stored.state.plan.fee,
            stored.state.plan.maximum_fee,
        )?;
        let submission_started_at = self.clock.now_unix()?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock()?;
            let current = store
                .load_workflow::<HnsSendWorkflow>(workflow_id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let mut state = current.state;
            state.stage = HnsSendStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store.save_workflow(
                workflow_id,
                WorkflowKind::HnsSend,
                current.revision,
                &state,
                true,
                submission_started_at,
            )?;
            (revision, state)
        };
        let actual = self.backend.broadcast_transaction(&raw)?;
        if actual != expected {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let current = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = current.state;
        state.stage = HnsSendStage::Broadcast;
        store.save_workflow(
            workflow_id,
            WorkflowKind::HnsSend,
            current.revision,
            &state,
            true,
            accepted_at,
        )?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid: actual,
            accepted_at_unix: accepted_at,
        })
    }

    pub fn import_name(&self, name: &[u8]) -> Result<KnownName, HnsWalletError> {
        let now = self.clock.now_unix()?;
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let config = cache.account.config.clone();
        drop(cache);
        let current = import_known_name(&self.backend, name, binding)?;
        let id = namespaced_name_id(&config, current.name_hash);
        let mut store = self.store_lock()?;
        let revision = store
            .known_name::<KnownName>(&id)?
            .map_or(0, |stored| stored.revision);
        store.save_known_name(&id, revision, &current, now)?;
        Ok(current)
    }

    pub fn cancel_prepared_send(&self, workflow_id: WorkflowId) -> Result<(), HnsWalletError> {
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        let mut store = self.store_lock()?;
        let stored = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.state.plan.wallet_id != config.wallet_id
            || stored.state.plan.account_id != config.account_id
            || stored.state.stage != HnsSendStage::Prepared
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = stored.state;
        state.stage = HnsSendStage::Cancelled;
        let deletes = reservation_deletes(&store, &config, workflow_id)?;
        store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            workflow_id,
            WorkflowKind::HnsSend,
            stored.revision,
            &state,
            false,
            now,
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
        Ok(())
    }

    pub fn cancel_prepared_settlement(
        &self,
        artifact: &PreparedArtifact,
    ) -> Result<(), HnsWalletError> {
        if artifact.module != ModuleId::Handshake {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let prepared: HnsPreparedSettlement = serde_json::from_slice(artifact.commitment_bytes())?;
        if prepared.stage != HnsSettlementStage::Prepared
            || prepared.session_id != artifact.session_id
            || prepared.fee != artifact.fee
            || prepared.expires_at_unix != artifact.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        let kind = settlement_workflow_kind(prepared.action);
        let mut store = self.store_lock()?;
        let mut stored = store
            .load_workflow::<HnsPreparedSettlement>(prepared.workflow_id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if stored.kind != kind
            || stored.state.stage != HnsSettlementStage::Prepared
            || !same_prepared_settlement(&stored.state, &prepared)
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        stored.state.stage = HnsSettlementStage::Cancelled;
        let deletes = if stored.state.action == HnsSettlementAction::Lock {
            reservation_deletes(&store, &config, stored.id)?
        } else {
            Vec::new()
        };
        store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
            stored.id,
            kind,
            stored.revision,
            &stored.state,
            false,
            now,
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
        Ok(())
    }

    pub fn settlement_key_target(
        &self,
        session_id: SessionId,
        refund: bool,
    ) -> Result<String, HnsWalletError> {
        let account = self.cache_read()?.account.clone();
        derive_settlement_public_key(&self.store_lock()?, &account, session_id, refund)
            .map(hex::encode)
    }

    pub fn broadcast_prepared_settlement(
        &self,
        artifact: &PreparedArtifact,
    ) -> Result<BroadcastReceipt, HnsWalletError> {
        if artifact.module != ModuleId::Handshake {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let prepared: HnsPreparedSettlement = serde_json::from_slice(artifact.commitment_bytes())?;
        if prepared.session_id != artifact.session_id
            || prepared.stage != HnsSettlementStage::Prepared
            || prepared.fee != artifact.fee
            || prepared.maximum_fee.is_zero()
            || prepared.fee > prepared.maximum_fee
            || prepared.expires_at_unix != artifact.expires_at_unix
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let artifact_quote = prepared
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        validate_final_fee_quote(
            &prepared.signed_transaction,
            artifact_quote,
            artifact_quote.binding,
            artifact_quote.mempool,
            prepared.fee,
            prepared.maximum_fee,
        )?;
        let transaction =
            decode_transaction_for_id(&prepared.signed_transaction, prepared.transaction)?;
        let transaction_id = wallet_transaction_hash(&transaction)?;
        if transaction_id != prepared.transaction {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let now = self.clock.now_unix()?;
        let config = self.cache_read()?.account.config.clone();
        if prepared.wallet_id != config.wallet_id || prepared.account_id != config.account_id {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let kind = settlement_workflow_kind(prepared.action);
        let stored = {
            let mut store = self.store_lock()?;
            let mut stored = store
                .load_workflow::<HnsPreparedSettlement>(prepared.workflow_id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if stored.kind != kind || !same_prepared_settlement(&stored.state, &prepared) {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            if stored.state.stage == HnsSettlementStage::Confirmed {
                return Ok(BroadcastReceipt {
                    module: ModuleId::Handshake,
                    txid: stored.state.transaction,
                    accepted_at_unix: now,
                });
            }
            if now >= stored.state.expires_at_unix {
                if stored.state.stage == HnsSettlementStage::Prepared {
                    stored.state.stage = HnsSettlementStage::Expired;
                    let deletes = if stored.state.action == HnsSettlementAction::Lock {
                        reservation_deletes(&store, &config, stored.id)?
                    } else {
                        Vec::new()
                    };
                    store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                        stored.id,
                        kind,
                        stored.revision,
                        &stored.state,
                        false,
                        now,
                        EntityKind::InputReservation,
                        &[],
                        &deletes,
                    )?;
                }
                return Err(HnsWalletError::PreparedArtifactExpired);
            }
            if !matches!(
                stored.state.stage,
                HnsSettlementStage::Prepared
                    | HnsSettlementStage::Broadcast
                    | HnsSettlementStage::Mempool
                    | HnsSettlementStage::RequiresRebroadcast
            ) {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            validate_final_fee_quote(
                &stored.state.signed_transaction,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.fee,
                stored.state.maximum_fee,
            )?;
            stored
        };
        let quote = self.quote_final_transaction(
            &stored.state.signed_transaction,
            stored.state.fee,
            stored.state.maximum_fee,
        )?;
        let submission_started_at = self.clock.now_unix()?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock()?;
            let current = store
                .load_workflow::<HnsPreparedSettlement>(stored.id)?
                .ok_or(HnsWalletError::InvalidWorkflow)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(HnsWalletError::InvalidWorkflow);
            }
            let activate = current.state.action == HnsSettlementAction::Lock
                && current.state.stage == HnsSettlementStage::Prepared;
            let activation_saves = if activate {
                reservation_activation_saves(&store, &config, current.id, submission_started_at)?
            } else {
                Vec::new()
            };
            let mut state = current.state;
            state.stage = HnsSettlementStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store.save_workflow_with_entity_batch(
                current.id,
                kind,
                current.revision,
                &state,
                true,
                submission_started_at,
                EntityKind::InputReservation,
                &activation_saves,
                &[],
            )?;
            (revision, state)
        };
        let accepted = self
            .backend
            .broadcast_transaction(&stored.state.signed_transaction)?;
        if accepted != stored.state.transaction {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix()?;
        let mut store = self.store_lock()?;
        let current = store
            .load_workflow::<HnsPreparedSettlement>(stored.id)?
            .ok_or(HnsWalletError::InvalidWorkflow)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let mut state = current.state;
        state.stage = HnsSettlementStage::Broadcast;
        store.save_workflow(
            stored.id,
            kind,
            current.revision,
            &state,
            true,
            accepted_at,
        )?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid: accepted,
            accepted_at_unix: accepted_at,
        })
    }

    fn persist_prepared_settlement(
        &self,
        session_id: SessionId,
        action: HnsSettlementAction,
        signed_transaction: Vec<u8>,
        fee: BaseUnits,
        maximum_fee: BaseUnits,
        fee_quote: HnsTransactionFeeQuote,
        terms: HnsSettlementTerms,
        reservation_saves: &[EntityBatchSave<HnsInputReservation>],
        account_save: Option<&EntityBatchSave<HnsAccountRecord>>,
        now_unix: u64,
    ) -> Result<PreparedArtifact, HnsWalletError> {
        let account = self.cache_read()?.account.clone();
        let transaction = Transaction::decode(&signed_transaction)
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        let transaction = wallet_transaction_hash(&transaction)?;
        validate_final_fee_quote(
            &signed_transaction,
            &fee_quote,
            fee_quote.binding,
            fee_quote.mempool,
            fee,
            maximum_fee,
        )?;
        let workflow_id = settlement_workflow_id(&account.config, session_id, action);
        let expires_at_unix = now_unix
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(HnsWalletError::Arithmetic)?;
        let prepared = HnsPreparedSettlement {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            session_id,
            action,
            stage: HnsSettlementStage::Prepared,
            transaction,
            signed_transaction,
            fee,
            maximum_fee,
            fee_quote: Some(fee_quote),
            expires_at_unix,
            terms,
        };
        let kind = settlement_workflow_kind(action);
        let artifact = Self::prepared_settlement_artifact(&prepared)?;
        let mut store = self.store_lock()?;
        match store.load_workflow::<HnsPreparedSettlement>(workflow_id)? {
            Some(stored) if stored.state == prepared && stored.kind == kind => {}
            Some(_) => return Err(HnsWalletError::InvalidWorkflow),
            None => {
                if let Some(account_save) = account_save {
                    let (_, next_account_revision) = store
                        .save_workflow_with_account_and_entity_batch(
                            workflow_id,
                            kind,
                            0,
                            &prepared,
                            true,
                            now_unix,
                            account_save,
                            EntityKind::InputReservation,
                            reservation_saves,
                            &[],
                        )?;
                    self.install_committed_account(
                        account_save.expected_revision,
                        next_account_revision,
                        account_save.value.clone(),
                    )?;
                } else {
                    store.save_workflow_with_entity_batch(
                        workflow_id,
                        kind,
                        0,
                        &prepared,
                        true,
                        now_unix,
                        EntityKind::InputReservation,
                        reservation_saves,
                        &[],
                    )?;
                }
            }
        }
        Ok(artifact)
    }

    fn prepare_settlement_spend(
        &self,
        session_id: SessionId,
        lock: VerifiedLock,
        preimage: Option<Preimage>,
        maximum_fee: BaseUnits,
        current_height: Option<u64>,
        action: HnsSettlementAction,
    ) -> Result<PreparedArtifact, ChainError> {
        if lock.module != ModuleId::Handshake
            || lock.session_id != session_id
            || maximum_fee.is_zero()
        {
            return Err(ChainError::InvalidRequest(
                "invalid Handshake settlement spend",
            ));
        }
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        if action == HnsSettlementAction::Refund
            && (current_height != Some(cache.sync.validated_height)
                || cache.sync.validated_height < lock.absolute_timelock)
        {
            return Err(ChainError::InvalidRequest(
                "refund height is not current or mature",
            ));
        }
        let account = cache.account.clone();
        drop(cache);
        let config = account.config.clone();
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let record = store
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&settlement_entity_id(
                &config, session_id,
            ))
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?
            .value;
        if record.verified != lock {
            return Err(ChainError::InvalidEvidence);
        }
        let refund = action == HnsSettlementAction::Refund;
        let public = derive_settlement_public_key(&store, &account, session_id, refund)
            .map_err(map_chain_error)?;
        let expected_key = if refund {
            decode_compressed_key(&record.expected.refund_target)?
        } else {
            decode_compressed_key(&record.expected.receiver)?
        };
        if public != expected_key {
            return Err(ChainError::InvalidRequest(
                "settlement target is not controlled by this wallet",
            ));
        }
        let receive_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 0,
            index: account.next_receive_index,
        };
        let receive_public = derive_hns_public_key(&store, config.wallet_id, receive_derivation)
            .map_err(map_chain_error)?;
        let destination = Address::new(
            0,
            public_key_hash(&receive_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidEvidence)?;
        let previous_value =
            u64::try_from(lock.amount.base_units.get()).map_err(|_| ChainError::InvalidEvidence)?;
        let sequence = if refund { u32::MAX - 1 } else { u32::MAX };
        let locktime = if refund {
            u32::try_from(lock.absolute_timelock).map_err(|_| ChainError::InvalidEvidence)?
        } else {
            0
        };
        let mut transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: CanonicalTransactionHash::new(lock.funding_id.into_bytes()),
                    index: record.output_index,
                },
                sequence,
                witness: Witness {
                    items: if refund {
                        vec![vec![0; 65], Vec::new(), record.script.clone()]
                    } else {
                        vec![
                            vec![0; 65],
                            vec![0; Preimage::LENGTH],
                            vec![1],
                            record.script.clone(),
                        ]
                    },
                },
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(previous_value),
                address: destination,
                covenant: Covenant::default(),
            }],
            locktime,
        };
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let fee = transaction_fee(&transaction, fee_rate).map_err(map_chain_error)?;
        if fee > maximum_fee
            || fee.get() >= u128::from(previous_value)
            || u128::from(previous_value) - fee.get() < config.dust_threshold.get()
        {
            return Err(ChainError::FeeLimit);
        }
        transaction.outputs[0].value = Dollarydoos::new(
            previous_value - u64::try_from(fee.get()).map_err(|_| ChainError::Overflow)?,
        );
        let unsigned_transaction = transaction.clone();
        let signed = sign_htlc_spend(
            &store,
            &account,
            transaction,
            session_id,
            &record.script,
            previous_value,
            preimage.as_ref(),
            refund,
        )
        .map_err(map_chain_error)?;
        validate_witness_only_change(&unsigned_transaction, &signed).map_err(map_chain_error)?;
        drop(store);
        let quote = self
            .quote_final_transaction(&signed, fee, maximum_fee)
            .map_err(map_chain_error)?;
        if self.cache_read().map_err(map_chain_error)?.account != account {
            return Err(ChainError::InvalidEvidence);
        }
        let terms = match action {
            HnsSettlementAction::Redeem => HnsSettlementTerms::Redeem { lock },
            HnsSettlementAction::Refund => HnsSettlementTerms::Refund { lock },
            HnsSettlementAction::Lock => {
                return Err(ChainError::InvalidRequest(
                    "invalid settlement spend action",
                ));
            }
        };
        self.persist_prepared_settlement(
            session_id,
            action,
            signed,
            fee,
            maximum_fee,
            quote,
            terms,
            &[],
            None,
            now,
        )
        .map_err(map_chain_error)
    }

    pub fn reconcile(&self) -> Result<HnsReconciliationReport, HnsWalletError> {
        let now = self.clock.now_unix()?;
        self.set_sync_phase(SyncPhase::Headers, None)?;
        let tip = self.backend.get_chain_tip()?;
        let (cached_account, cached_account_revision) = {
            let cache = self.cache_read()?;
            (cache.account.clone(), cache.account_revision)
        };
        let mut store = self.store_lock()?;
        let stored_account = store
            .wallet_account::<HnsAccountRecord>(&account_entity_id(&cached_account.config))?
            .ok_or(HnsWalletError::InvalidEvidence)?;
        validate_authoritative_reconcile_account(
            &cached_account,
            cached_account_revision,
            &stored_account.value,
            stored_account.revision,
        )?;
        let stored_account_revision = stored_account.revision;
        let account = stored_account.value;
        let stored_recovery: Option<StoredEntity<HnsRecoveryState>> =
            store.hns_recovery_state(&recovery_entity_id(&account.config))?;
        let (mut recovery, recovery_revision) = stored_recovery
            .map_or((HnsRecoveryState::default(), 0), |stored| {
                (stored.value, stored.revision)
            });
        self.set_sync_phase(SyncPhase::WalletScan, None)?;
        let (
            account,
            account_revision,
            binding,
            mempool_binding,
            addresses,
            history,
            indexed_coins,
        ) = self.restore_scan(
            &mut store,
            account,
            stored_account_revision,
            tip,
            now,
        )?;
        let common_ancestor = self.find_common_ancestor(&recovery, binding)?;
        let reorg_detected = recovery.last_tip.is_some()
            && common_ancestor
                != recovery
                    .last_tip
                    .map(|old_tip| old_tip.height.min(tip.height));
        let coins = reconcile_coins(indexed_coins, &addresses)?;
        let transactions = self.reconcile_transactions(
            &history,
            &addresses,
            binding,
            mempool_binding,
            common_ancestor,
        )?;
        let revalidated_names = self.revalidate_names(&mut store, binding, now)?;
        persist_reconciled_entities(&mut store, &account.config, &coins, &transactions, now)?;
        let mut pending_user_actions =
            self.reconcile_send_workflows(&mut store, binding, mempool_binding, now)?;
        pending_user_actions.extend(self.reconcile_settlement_workflows(
            &mut store,
            binding,
            mempool_binding,
            now,
        )?);
        pending_user_actions.sort();
        pending_user_actions.dedup();
        self.cleanup_input_reservations(
            &mut store,
            &account.config,
            &coins,
            binding,
            mempool_binding,
            now,
        )?;

        recovery.checkpoints = self.refresh_checkpoints(binding)?;
        recovery.last_tip = Some(tip);
        recovery.last_common_ancestor = common_ancestor;
        recovery.last_reconciled_unix = now;
        store.save_hns_recovery_state(
            &recovery_entity_id(&account.config),
            recovery_revision,
            &recovery,
            now,
        )?;

        {
            let mut cache = self.cache_write()?;
            validate_authoritative_reconcile_account(
                &cache.account,
                cache.account_revision,
                &account,
                account_revision,
            )?;
            cache.account = account;
            cache.account_revision = account_revision;
            cache.sync = SyncStatus {
                phase: SyncPhase::Ready,
                validated_height: tip.height,
                scanned_height: tip.height,
                target_height: Some(tip.height),
                last_error: None,
            };
            cache.coins = coins.clone();
            cache.transactions = transactions.clone();
            cache.binding = Some(binding);
            cache.mempool_binding = Some(mempool_binding);
        }
        drop(store);
        Ok(HnsReconciliationReport {
            tip,
            common_ancestor,
            reorg_detected,
            restored_utxos: coins.len(),
            reconciled_transactions: transactions.len(),
            revalidated_names,
            pending_user_actions,
        })
    }

    fn find_common_ancestor(
        &self,
        recovery: &HnsRecoveryState,
        binding: SnapshotBinding,
    ) -> Result<Option<u64>, HnsWalletError> {
        let tip = binding.tip;
        if recovery.last_tip.is_none() {
            return Ok(None);
        }
        for checkpoint in recovery.checkpoints.iter().rev() {
            if checkpoint.height > tip.height {
                continue;
            }
            let evidence = self.backend.get_block_hash(checkpoint.height, binding)?;
            if evidence.binding != binding || evidence.height != checkpoint.height {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            if evidence.block_hash == Some(checkpoint.block_hash) {
                return Ok(Some(checkpoint.height));
            }
        }
        Ok(account_birthday_ancestor(
            self.cache_read()?.account.config.birthday_height,
        ))
    }

    fn refresh_checkpoints(
        &self,
        binding: SnapshotBinding,
    ) -> Result<Vec<HnsChainCheckpoint>, HnsWalletError> {
        let tip = binding.tip;
        let birthday = self.cache_read()?.account.config.birthday_height;
        let start = tip
            .height
            .saturating_sub((MAX_RECOVERY_CHECKPOINTS - 1) as u64)
            .max(birthday);
        let mut checkpoints = Vec::new();
        for height in start..=tip.height {
            let block_hash = if height == tip.height {
                Some(tip.block_hash)
            } else {
                let evidence = self.backend.get_block_hash(height, binding)?;
                if evidence.binding != binding || evidence.height != height {
                    return Err(HnsWalletError::StaleNodeSnapshot);
                }
                evidence.block_hash
            };
            let block_hash = block_hash.ok_or(HnsWalletError::InvalidEvidence)?;
            checkpoints.push(HnsChainCheckpoint { height, block_hash });
        }
        Ok(checkpoints)
    }

    fn set_sync_phase(
        &self,
        phase: SyncPhase,
        last_error: Option<String>,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        cache.sync.phase = phase;
        cache.sync.last_error = last_error;
        Ok(())
    }

    fn change_account_save(
        account: &HnsAccountRecord,
        account_revision: u64,
        used_index: u32,
        now_unix: u64,
    ) -> Result<EntityBatchSave<HnsAccountRecord>, HnsWalletError> {
        if account.next_change_index != used_index {
            return Err(HnsWalletError::StaleAddressReservation);
        }
        let next = used_index
            .checked_add(1)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
        ensure_trailing_gap(Some(used_index), account.config.restore_lookahead)?;
        let mut next_account = account.clone();
        next_account.next_change_index = next;
        next_account.internal_scan_end = next_account.internal_scan_end.max(required_scan_end(
            Some(used_index),
            next_account.internal_scan_end,
            next_account.config.restore_lookahead,
        ));
        Ok(EntityBatchSave {
            id: account_entity_id(&next_account.config).to_vec(),
            expected_revision: account_revision,
            value: next_account,
            updated_at_unix: now_unix,
        })
    }

    fn install_committed_account(
        &self,
        expected_revision: u64,
        next_revision: u64,
        next_account: HnsAccountRecord,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        if cache.account_revision != expected_revision {
            if cache.account_revision == next_revision && cache.account == next_account {
                return Ok(());
            }
            return Err(HnsWalletError::StaleAddressReservation);
        }
        cache.account = next_account;
        cache.account_revision = next_revision;
        Ok(())
    }

    fn install_loaded_account(
        &self,
        loaded: StoredEntity<HnsAccountRecord>,
    ) -> Result<(), HnsWalletError> {
        let mut cache = self.cache_write()?;
        if !same_account_identity(&cache.account.config, &loaded.value.config) {
            return Err(HnsWalletError::AccountConfigurationMismatch);
        }
        if loaded.revision < cache.account_revision {
            return Ok(());
        }
        if loaded.revision == cache.account_revision && loaded.value != cache.account {
            return Err(HnsWalletError::AccountConfigurationMismatch);
        }
        cache.account = loaded.value;
        cache.account_revision = loaded.revision;
        Ok(())
    }

    fn prepared_send_from_plan(plan: &HnsSpendPlan) -> Result<PreparedSend, ChainError> {
        let payload = serde_json::to_vec(plan)
            .map_err(|_| ChainError::Backend("prepared send encoding failed".to_owned()))?;
        PreparedSend::new(
            ModuleId::Handshake,
            Amount {
                asset: WalletAsset::Hns,
                base_units: plan.amount,
            },
            plan.fee,
            plan.destination.clone(),
            plan.expires_at_unix,
            payload,
        )
    }

    fn recover_prepared_send(
        stored: &StoredWorkflow<HnsSendWorkflow>,
        request: &SendRequest,
        config: &HnsRuntimeConfig,
        workflow_id: WorkflowId,
        now_unix: u64,
    ) -> Result<PreparedSend, ChainError> {
        let state = &stored.state;
        if stored.kind != WorkflowKind::HnsSend
            || state.stage != HnsSendStage::Prepared
            || state.transaction.is_some()
            || state.signed_transaction.is_some()
            || state.fee_quote.is_some()
            || state.plan.wallet_id != config.wallet_id
            || state.plan.account_id != config.account_id
            || state.plan.workflow_id != workflow_id
            || state.plan.request_nonce != request.request_nonce
            || state.plan.amount != request.amount.base_units
            || state.plan.maximum_fee != request.maximum_fee
            || state.plan.fee > state.plan.maximum_fee
            || state.plan.destination != request.destination
            || state.plan.inputs.is_empty()
            || state
                .plan
                .inputs
                .iter()
                .any(|input| !is_ordinary_hns_derivation(input.derivation))
            || state.plan.expires_at_unix <= now_unix
        {
            return Err(ChainError::InvalidRequest(
                "persisted Handshake send does not match retry",
            ));
        }
        Self::prepared_send_from_plan(&state.plan)
    }

    fn prepared_settlement_artifact(
        prepared: &HnsPreparedSettlement,
    ) -> Result<PreparedArtifact, HnsWalletError> {
        let decoded = Transaction::decode(&prepared.signed_transaction)
            .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
        if wallet_transaction_hash(&decoded)? != prepared.transaction {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let fee_quote = prepared
            .fee_quote
            .as_ref()
            .ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        validate_final_fee_quote(
            &prepared.signed_transaction,
            fee_quote,
            fee_quote.binding,
            fee_quote.mempool,
            prepared.fee,
            prepared.maximum_fee,
        )?;
        let payload = serde_json::to_vec(prepared)?;
        PreparedArtifact::new(
            ModuleId::Handshake,
            prepared.session_id,
            prepared.fee,
            prepared.expires_at_unix,
            payload,
        )
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
    }

    fn restore_scan(
        &self,
        store: &mut WalletStore,
        mut account: HnsAccountRecord,
        expected_account_revision: u64,
        expected_tip: ChainTip,
        now_unix: u64,
    ) -> Result<
        (
            HnsAccountRecord,
            u64,
            SnapshotBinding,
            MempoolSnapshotBinding,
            Vec<DerivedHnsAddress>,
            Vec<HistoryEntry>,
            Vec<IndexedWalletCoin>,
        ),
        HnsWalletError,
    > {
        if account.external_scan_end >= MAX_RESTORE_LOOKAHEAD
            || account.internal_scan_end >= MAX_RESTORE_LOOKAHEAD
            || account.name_scan_end >= MAX_RESTORE_LOOKAHEAD
            || account.next_receive_index >= MAX_RESTORE_LOOKAHEAD
            || account.next_change_index >= MAX_RESTORE_LOOKAHEAD
            || account.next_name_index >= MAX_RESTORE_LOOKAHEAD
        {
            return Err(HnsWalletError::InvalidLookahead);
        }
        let gap = account.config.restore_lookahead;
        let minimum_external_end = account
            .next_receive_index
            .saturating_add(gap - 1)
            .min(MAX_RESTORE_LOOKAHEAD - 1);
        let minimum_internal_end = account
            .next_change_index
            .saturating_add(gap - 1)
            .min(MAX_RESTORE_LOOKAHEAD - 1);
        let minimum_name_end = account
            .next_name_index
            .saturating_add(gap - 1)
            .min(MAX_RESTORE_LOOKAHEAD - 1);
        account.external_scan_end = account.external_scan_end.max(minimum_external_end);
        account.internal_scan_end = account.internal_scan_end.max(minimum_internal_end);
        account.name_scan_end = account.name_scan_end.max(minimum_name_end);

        let mut expected_binding = None;
        let mut expected_mempool = None;
        let (mut addresses, mut history, indexed_coins, binding, mempool_binding) = loop {
            let coin_addresses =
                derive_restore_addresses(store, &account, KeyRole::HnsCoin)?;
            let name_addresses =
                derive_restore_addresses(store, &account, KeyRole::HnsName)?;
            validate_disjoint_restore_programs(&coin_addresses, &name_addresses)?;

            let (coin_scripts, coin_index_remap) = sorted_restore_scripts(&coin_addresses)?;
            let (binding, mempool_binding, coin_history, coin_coins) = load_wallet_snapshot(
                &self.backend,
                &coin_scripts,
                &coin_index_remap,
                expected_tip,
                expected_binding,
                expected_mempool,
            )?;
            if expected_binding.is_some_and(|expected| expected != binding) {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            if expected_mempool.is_some_and(|expected| expected != mempool_binding) {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }

            let (name_scripts, name_index_remap) = sorted_restore_scripts(&name_addresses)?;
            let (
                name_binding,
                name_mempool_binding,
                name_history,
                name_coins,
            ) = load_wallet_snapshot(
                &self.backend,
                &name_scripts,
                &name_index_remap,
                expected_tip,
                Some(binding),
                Some(mempool_binding),
            )?;
            validate_same_restore_snapshot(
                binding,
                mempool_binding,
                name_binding,
                name_mempool_binding,
            )?;
            expected_binding = Some(binding);
            expected_mempool = Some(mempool_binding);

            let mut addresses = Vec::new();
            let mut history = Vec::new();
            let mut indexed_coins = Vec::new();
            append_restore_branch(
                &mut addresses,
                &mut history,
                &mut indexed_coins,
                coin_addresses,
                coin_history,
                coin_coins,
            )?;
            append_restore_branch(
                &mut addresses,
                &mut history,
                &mut indexed_coins,
                name_addresses,
                name_history,
                name_coins,
            )?;

            let mut last_external = None;
            let mut last_internal = None;
            let mut last_name = None;
            for entry in &history {
                let derivation = addresses
                    .get(entry.script_index as usize)
                    .ok_or(HnsWalletError::InvalidEvidence)?
                    .derivation;
                match restore_derivation_key(derivation)? {
                    (HNS_COIN_DERIVATION_TAG, 0, index) => {
                        last_external = Some(
                            last_external
                                .map_or(index, |last: u32| last.max(index)),
                        )
                    }
                    (HNS_COIN_DERIVATION_TAG, 1, index) => {
                        last_internal = Some(
                            last_internal
                                .map_or(index, |last: u32| last.max(index)),
                        )
                    }
                    (HNS_NAME_DERIVATION_TAG, 0, index) => {
                        last_name = Some(last_name.map_or(index, |last: u32| last.max(index)))
                    }
                    _ => return Err(HnsWalletError::InvalidEvidence),
                }
            }
            ensure_trailing_gap(last_external, gap)?;
            ensure_trailing_gap(last_internal, gap)?;
            ensure_trailing_gap(last_name, gap)?;
            let required_external =
                required_scan_end(last_external, account.external_scan_end, gap);
            let required_internal =
                required_scan_end(last_internal, account.internal_scan_end, gap);
            let required_name = required_scan_end(last_name, account.name_scan_end, gap);
            checked_scan_address_count(&[required_external, required_internal])?;
            checked_scan_address_count(&[required_name])?;
            if required_external <= account.external_scan_end
                && required_internal <= account.internal_scan_end
                && required_name <= account.name_scan_end
            {
                break (
                    addresses,
                    history,
                    indexed_coins,
                    binding,
                    mempool_binding,
                );
            }
            account.external_scan_end = required_external;
            account.internal_scan_end = required_internal;
            account.name_scan_end = required_name;
        };

        let used: BTreeSet<(u8, u32, u32)> = history
            .iter()
            .map(|entry| -> Result<_, HnsWalletError> {
                let derivation = addresses[entry.script_index as usize].derivation;
                restore_derivation_key(derivation)
            })
            .collect::<Result<_, _>>()?;
        for address in &mut addresses {
            address.used = used.contains(&restore_derivation_key(address.derivation)?);
        }
        account.last_used_external = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_COIN_DERIVATION_TAG && *change == 0)
            .map(|(_, _, index)| *index)
            .max();
        account.last_used_internal = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_COIN_DERIVATION_TAG && *change == 1)
            .map(|(_, _, index)| *index)
            .max();
        account.last_used_name = used
            .iter()
            .filter(|(role, change, _)| *role == HNS_NAME_DERIVATION_TAG && *change == 0)
            .map(|(_, _, index)| *index)
            .max();
        account.next_receive_index = advance_next_derivation_index(
            account.next_receive_index,
            account.last_used_external,
        );
        account.next_change_index = advance_next_derivation_index(
            account.next_change_index,
            account.last_used_internal,
        );
        account.next_name_index =
            advance_next_derivation_index(account.next_name_index, account.last_used_name);
        persist_derived_addresses(store, &account.config, &addresses, now_unix)?;
        let account_revision = store.save_wallet_account(
            &account_entity_id(&account.config),
            expected_account_revision,
            &account,
            now_unix,
        )?;
        history.sort_by_key(|entry| (entry.txid, entry.script_index));
        Ok((
            account,
            account_revision,
            binding,
            mempool_binding,
            addresses,
            history,
            indexed_coins,
        ))
    }

    fn cache_read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, HnsRuntimeCache>, HnsWalletError> {
        self.cache
            .read()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }

    fn cache_write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, HnsRuntimeCache>, HnsWalletError> {
        self.cache
            .write()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }

    fn store_lock(&self) -> Result<std::sync::MutexGuard<'_, WalletStore>, HnsWalletError> {
        self.store
            .lock()
            .map_err(|_| HnsWalletError::RuntimePoisoned)
    }

    fn quote_final_transaction_once(
        &self,
        raw: &[u8],
        expected_fee: BaseUnits,
        maximum_fee: BaseUnits,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        let cache = self.cache_read()?;
        let binding = cache.binding.ok_or(HnsWalletError::StaleNodeSnapshot)?;
        let mempool = cache
            .mempool_binding
            .ok_or(HnsWalletError::StaleNodeSnapshot)?;
        drop(cache);
        let quote = self.backend.quote_transaction_fee(
            raw,
            DEFAULT_FEE_TARGET_BLOCKS,
            binding,
            mempool,
        )?;
        validate_final_fee_quote(raw, &quote, binding, mempool, expected_fee, maximum_fee)?;
        Ok(quote)
    }

    /// Performs at most one explicit reconciliation and one quote retry. This
    /// is a bounded recovery transition, not a polling loop.
    fn quote_final_transaction(
        &self,
        raw: &[u8],
        expected_fee: BaseUnits,
        maximum_fee: BaseUnits,
    ) -> Result<HnsTransactionFeeQuote, HnsWalletError> {
        match self.quote_final_transaction_once(raw, expected_fee, maximum_fee) {
            Err(HnsWalletError::StaleNodeSnapshot)
            | Err(HnsWalletError::FeeQuoteInputUnavailable) => {
                self.reconcile()?;
                self.quote_final_transaction_once(raw, expected_fee, maximum_fee)
            }
            result => result,
        }
    }
}

impl<B: HnsBackend, C: HnsClock> HnsWalletRuntime<B, C> {
    fn reconcile_transactions(
        &self,
        history: &[HistoryEntry],
        addresses: &[DerivedHnsAddress],
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        common_ancestor: Option<u64>,
    ) -> Result<Vec<HnsTransactionRecord>, HnsWalletError> {
        let mut history = coalesce_transaction_history(history)?;
        let observed_txids: BTreeSet<TransactionHash> =
            history.iter().map(|entry| entry.txid).collect();
        if addresses.is_empty()
            || addresses.len() > MAX_RESTORE_ADDRESS_RECORDS
            || addresses
                .iter()
                .any(|address| restore_derivation_key(address.derivation).is_err())
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let programs: BTreeSet<Vec<u8>> = addresses
            .iter()
            .map(|address| address.program.clone())
            .collect();
        if programs.len() != addresses.len() || programs.iter().any(|program| program.len() != 20) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let previous: BTreeMap<TransactionHash, TransactionSummary> = self
            .cache_read()?
            .transactions
            .iter()
            .map(|record| (record.summary.txid, record.summary.clone()))
            .collect();
        for summary in previous.values() {
            if !observed_txids.contains(&summary.txid) {
                history.push(HistoryEntry {
                    txid: summary.txid,
                    height: summary.block_height,
                    block_hash: None,
                    transaction_position: None,
                    spent: false,
                    first_seen_unix: summary.first_seen_unix,
                    script_index: 0,
                });
            }
        }
        let mut raw_cache = BTreeMap::new();
        let mut records = Vec::with_capacity(history.len());
        let persisted_raw: BTreeMap<TransactionHash, Vec<u8>> = self
            .cache_read()?
            .transactions
            .iter()
            .map(|record| (record.summary.txid, record.raw.clone()))
            .collect();
        for entry in &history {
            let evidence = self.backend.get_transaction_evidence(
                entry.txid,
                binding,
                Some(mempool_binding),
            )?;
            if evidence.binding != binding || evidence.mempool != mempool_binding {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let raw = match evidence.raw {
                Some(raw) => raw,
                None => persisted_raw
                    .get(&entry.txid)
                    .cloned()
                    .ok_or(HnsWalletError::InvalidEvidence)?,
            };
            let transaction = decode_transaction_for_id(&raw, entry.txid)?;
            raw_cache.insert(entry.txid, transaction.clone());
            let status = evidence.status;
            let competing_spender =
                self.has_competing_spender(entry.txid, &transaction, binding)?;
            let inclusion = evidence.inclusion;
            validate_inclusion(
                entry,
                status,
                inclusion,
                binding.tip,
                observed_txids.contains(&entry.txid),
            )?;
            let (net_amount, fee) = transaction_value_effect(
                &self.backend,
                &transaction,
                &programs,
                &mut raw_cache,
                &persisted_raw,
                binding,
                mempool_binding,
            )?;
            let current_status = if status.conflicted || competing_spender {
                LocalTransactionStatus::Conflicted
            } else if status.confirmation_count > 0 {
                LocalTransactionStatus::Confirmed
            } else if status.in_mempool {
                LocalTransactionStatus::Mempool
            } else if previous.get(&entry.txid).is_some_and(|old| {
                old.status == LocalTransactionStatus::Confirmed
                    && old.block_height.is_some_and(|height| {
                        common_ancestor.is_none_or(|ancestor| height > ancestor)
                    })
            }) {
                LocalTransactionStatus::Reorged
            } else {
                LocalTransactionStatus::Dropped
            };
            records.push(HnsTransactionRecord {
                summary: TransactionSummary {
                    module: ModuleId::Handshake,
                    txid: entry.txid,
                    status: current_status,
                    net_amount,
                    fee,
                    block_height: inclusion.map(|value| value.height),
                    first_seen_unix: entry.first_seen_unix,
                    confirmation_count: status.confirmation_count,
                },
                raw,
                inclusion,
            });
        }
        records.sort_by(|left, right| {
            right
                .summary
                .block_height
                .cmp(&left.summary.block_height)
                .then_with(|| {
                    right
                        .summary
                        .first_seen_unix
                        .cmp(&left.summary.first_seen_unix)
                })
                .then_with(|| left.summary.txid.cmp(&right.summary.txid))
        });
        Ok(records)
    }

    fn revalidate_names(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        now_unix: u64,
    ) -> Result<usize, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let names = store
            .known_names::<KnownName>(MAX_HISTORY_RESULTS)?
            .into_iter()
            .filter(|entity| entity.id.starts_with(&account_entity_prefix(&config)))
            .collect::<Vec<_>>();
        let mut count = 0;
        for stored in names {
            let current = validated_name_evidence(&self.backend, &stored.value.name, binding)?;
            if current.proof_height != binding.tip.height {
                return Err(HnsWalletError::InvalidEvidence);
            }
            store.save_known_name(
                &namespaced_name_id(&config, current.name_hash),
                stored.revision,
                &current,
                now_unix,
            )?;
            count += 1;
        }
        Ok(count)
    }

    fn reconcile_send_workflows(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<Vec<WorkflowId>, HnsWalletError> {
        let workflows =
            store.list_workflows::<HnsSendWorkflow>(WorkflowKind::HnsSend, MAX_HISTORY_RESULTS)?;
        let config = self.cache_read()?.account.config.clone();
        let mut pending = Vec::new();
        for stored in workflows {
            if stored.state.plan.wallet_id != config.wallet_id
                || stored.state.plan.account_id != config.account_id
            {
                continue;
            }
            if stored.state.stage == HnsSendStage::Prepared
                && stored.state.plan.expires_at_unix <= now_unix
            {
                let mut state = stored.state;
                state.stage = HnsSendStage::Expired;
                let deletes = reservation_deletes(store, &config, stored.id)?;
                store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                    stored.id,
                    WorkflowKind::HnsSend,
                    stored.revision,
                    &state,
                    false,
                    now_unix,
                    EntityKind::InputReservation,
                    &[],
                    &deletes,
                )?;
                continue;
            }
            let Some(txid) = stored.state.transaction else {
                continue;
            };
            let evidence = self.backend.get_transaction_evidence(
                txid,
                binding,
                Some(mempool_binding),
            )?;
            if evidence.binding != binding || evidence.mempool != mempool_binding {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let chain_status = evidence.status;
            let outpoints: Vec<HnsOutpoint> = stored
                .state
                .plan
                .inputs
                .iter()
                .map(|input| input.coin.outpoint)
                .collect();
            let competing_spender = has_competing_spender_in_batches(
                &self.backend,
                &outpoints,
                binding,
                txid,
            )?;
            let next_stage = if chain_status.conflicted || competing_spender {
                HnsSendStage::Conflicted
            } else if chain_status.confirmation_count > 0 {
                HnsSendStage::Confirmed
            } else if chain_status.in_mempool {
                HnsSendStage::Mempool
            } else if matches!(
                stored.state.stage,
                HnsSendStage::Authorized
                    | HnsSendStage::Broadcast
                    | HnsSendStage::Mempool
                    | HnsSendStage::RequiresRebroadcast
            ) {
                pending.push(stored.id);
                HnsSendStage::RequiresRebroadcast
            } else {
                stored.state.stage
            };
            if next_stage != stored.state.stage {
                let mut state = stored.state;
                state.stage = next_stage;
                let deletes = if matches!(
                    next_stage,
                    HnsSendStage::Confirmed | HnsSendStage::Conflicted
                ) {
                    reservation_deletes(store, &config, stored.id)?
                } else {
                    Vec::new()
                };
                store.save_workflow_with_entity_batch::<_, HnsInputReservation>(
                    stored.id,
                    WorkflowKind::HnsSend,
                    stored.revision,
                    &state,
                    state.signed_transaction.is_some(),
                    now_unix,
                    EntityKind::InputReservation,
                    &[],
                    &deletes,
                )?;
            }
        }
        Ok(pending)
    }

    fn has_competing_spender(
        &self,
        transaction_id: TransactionHash,
        transaction: &Transaction,
        binding: SnapshotBinding,
    ) -> Result<bool, HnsWalletError> {
        let mut outpoints = Vec::new();
        for input in &transaction.inputs {
            if input.previous_output.is_null() {
                continue;
            }
            let outpoint = HnsOutpoint {
                transaction: TransactionHash::new(
                    input.previous_output.transaction_hash.into_bytes(),
                ),
                output_index: input.previous_output.index,
            };
            outpoints.push(outpoint);
        }
        has_competing_spender_in_batches(&self.backend, &outpoints, binding, transaction_id)
    }

    fn cleanup_input_reservations(
        &self,
        store: &mut WalletStore,
        config: &HnsRuntimeConfig,
        coins: &[TrackedHnsCoin],
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<(), HnsWalletError> {
        let unspent: BTreeSet<HnsOutpoint> = coins
            .iter()
            .filter(|coin| is_ordinary_hns_derivation(coin.derivation))
            .map(|coin| coin.coin.outpoint)
            .collect();
        let reservations = store.input_reservations::<HnsInputReservation>(MAX_WALLET_COINS)?;
        let mut deletes = Vec::new();
        for stored in reservations {
            if stored.value.wallet_id != config.wallet_id
                || stored.value.account_id != config.account_id
            {
                continue;
            }
            let expired = stored
                .value
                .expires_at_unix
                .is_some_and(|expiry| expiry <= now_unix);
            let spent = !unspent.contains(&stored.value.outpoint);
            let conflicted = if stored.value.expires_at_unix.is_none() {
                match store.load_workflow::<HnsPreparedSettlement>(stored.value.workflow_id) {
                    Ok(Some(workflow)) => {
                        let evidence = self
                            .backend
                            .get_transaction_evidence(
                                workflow.state.transaction,
                                binding,
                                Some(mempool_binding),
                            )?;
                        if evidence.binding != binding || evidence.mempool != mempool_binding {
                            return Err(HnsWalletError::StaleNodeSnapshot);
                        }
                        evidence.status.conflicted
                    }
                    Ok(None) => true,
                    Err(_) => false,
                }
            } else {
                false
            };
            if expired || spent || conflicted {
                deletes.push(EntityBatchDelete {
                    id: stored.id,
                    expected_revision: stored.revision,
                });
            }
        }
        if !deletes.is_empty() {
            store.apply_entity_batch::<HnsInputReservation>(
                EntityKind::InputReservation,
                &[],
                &deletes,
            )?;
        }
        Ok(())
    }

    fn reconcile_settlement_workflows(
        &self,
        store: &mut WalletStore,
        binding: SnapshotBinding,
        mempool_binding: MempoolSnapshotBinding,
        now_unix: u64,
    ) -> Result<Vec<WorkflowId>, HnsWalletError> {
        let config = self.cache_read()?.account.config.clone();
        let mut pending = Vec::new();
        for kind in [WorkflowKind::AtomicSwap, WorkflowKind::Refund] {
            let workflows =
                store.list_workflows::<HnsPreparedSettlement>(kind, MAX_HISTORY_RESULTS)?;
            for mut stored in workflows {
                if stored.state.wallet_id != config.wallet_id
                    || stored.state.account_id != config.account_id
                    || settlement_workflow_kind(stored.state.action) != kind
                {
                    continue;
                }
                let previous_stage = stored.state.stage;
                let next_stage = if previous_stage == HnsSettlementStage::Prepared {
                    let evidence = self
                        .backend
                        .get_transaction_evidence(
                            stored.state.transaction,
                            binding,
                            Some(mempool_binding),
                        )?;
                    if evidence.binding != binding || evidence.mempool != mempool_binding {
                        return Err(HnsWalletError::StaleNodeSnapshot);
                    }
                    if evidence.status.conflicted {
                        HnsSettlementStage::Conflicted
                    } else if evidence.status.confirmation_count > 0 {
                        HnsSettlementStage::Confirmed
                    } else if evidence.status.in_mempool {
                        HnsSettlementStage::Mempool
                    } else if stored.state.expires_at_unix <= now_unix {
                        HnsSettlementStage::Expired
                    } else {
                        previous_stage
                    }
                } else if matches!(
                    previous_stage,
                    HnsSettlementStage::Broadcast
                        | HnsSettlementStage::Mempool
                        | HnsSettlementStage::RequiresRebroadcast
                ) {
                    let evidence = self
                        .backend
                        .get_transaction_evidence(
                            stored.state.transaction,
                            binding,
                            Some(mempool_binding),
                        )?;
                    if evidence.binding != binding || evidence.mempool != mempool_binding {
                        return Err(HnsWalletError::StaleNodeSnapshot);
                    }
                    if evidence.status.conflicted {
                        HnsSettlementStage::Conflicted
                    } else if evidence.status.confirmation_count > 0 {
                        HnsSettlementStage::Confirmed
                    } else if evidence.status.in_mempool {
                        HnsSettlementStage::Mempool
                    } else if stored.state.expires_at_unix <= now_unix {
                        HnsSettlementStage::Expired
                    } else {
                        pending.push(stored.id);
                        HnsSettlementStage::RequiresRebroadcast
                    }
                } else {
                    previous_stage
                };
                let terminal_lock = stored.state.action == HnsSettlementAction::Lock
                    && matches!(
                        next_stage,
                        HnsSettlementStage::Confirmed
                            | HnsSettlementStage::Conflicted
                            | HnsSettlementStage::Expired
                            | HnsSettlementStage::Cancelled
                    );
                if next_stage != previous_stage {
                    stored.state.stage = next_stage;
                    let deletes = if terminal_lock {
                        reservation_deletes(store, &config, stored.id)?
                    } else {
                        Vec::new()
                    };
                    let saves = if stored.state.action == HnsSettlementAction::Lock
                        && previous_stage == HnsSettlementStage::Prepared
                        && next_stage == HnsSettlementStage::Mempool
                    {
                        reservation_activation_saves(store, &config, stored.id, now_unix)?
                    } else {
                        Vec::new()
                    };
                    store.save_workflow_with_entity_batch(
                        stored.id,
                        kind,
                        stored.revision,
                        &stored.state,
                        !matches!(
                            next_stage,
                            HnsSettlementStage::Prepared
                                | HnsSettlementStage::Expired
                                | HnsSettlementStage::Cancelled
                        ),
                        now_unix,
                        EntityKind::InputReservation,
                        &saves,
                        &deletes,
                    )?;
                } else if terminal_lock {
                    release_reservations(store, &config, stored.id)?;
                }
            }
        }
        Ok(pending)
    }
}

fn account_number(account: &HnsAccountRecord) -> u32 {
    account.config.account_derivation_index
}

fn same_account_identity(left: &HnsRuntimeConfig, right: &HnsRuntimeConfig) -> bool {
    left.wallet_id == right.wallet_id
        && left.account_id == right.account_id
        && left.account_derivation_index == right.account_derivation_index
        && left.network == right.network
        && left.birthday_height == right.birthday_height
}

fn validate_authoritative_reconcile_account(
    cached: &HnsAccountRecord,
    cached_revision: u64,
    authoritative: &HnsAccountRecord,
    authoritative_revision: u64,
) -> Result<(), HnsWalletError> {
    if !same_account_identity(&cached.config, &authoritative.config)
        || cached.config != authoritative.config
    {
        return Err(HnsWalletError::AccountConfigurationMismatch);
    }
    if authoritative_revision < cached_revision
        || (authoritative_revision == cached_revision && authoritative != cached)
        || authoritative.next_receive_index < cached.next_receive_index
        || authoritative.next_change_index < cached.next_change_index
        || authoritative.next_name_index < cached.next_name_index
        || authoritative.external_scan_end < cached.external_scan_end
        || authoritative.internal_scan_end < cached.internal_scan_end
        || authoritative.name_scan_end < cached.name_scan_end
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(())
}

fn account_birthday_ancestor(birthday_height: u64) -> Option<u64> {
    birthday_height.checked_sub(1)
}

fn ensure_trailing_gap(last_used: Option<u32>, gap: u32) -> Result<(), HnsWalletError> {
    if last_used.is_some_and(|index| index.saturating_add(gap) >= MAX_RESTORE_LOOKAHEAD) {
        Err(HnsWalletError::ScanCapacityExhausted)
    } else {
        Ok(())
    }
}

fn required_scan_end(last_used: Option<u32>, current: u32, gap: u32) -> u32 {
    last_used.map_or(current, |index| current.max(index.saturating_add(gap)))
}

fn advance_next_derivation_index(current: u32, last_used: Option<u32>) -> u32 {
    last_used.map_or(current, |last_used| {
        current
            .max(last_used.saturating_add(1))
            .min(MAX_RESTORE_LOOKAHEAD - 1)
    })
}

const HNS_COIN_DERIVATION_TAG: u8 = 0;
const HNS_NAME_DERIVATION_TAG: u8 = 1;

fn restore_derivation_key(
    derivation: DerivationReference,
) -> Result<(u8, u32, u32), HnsWalletError> {
    if derivation.index >= MAX_RESTORE_LOOKAHEAD {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match (derivation.role, derivation.change) {
        (KeyRole::HnsCoin, change) if change <= 1 => {
            Ok((HNS_COIN_DERIVATION_TAG, change, derivation.index))
        }
        (KeyRole::HnsName, 0) => Ok((HNS_NAME_DERIVATION_TAG, 0, derivation.index)),
        _ => Err(HnsWalletError::InvalidEvidence),
    }
}

fn checked_scan_address_count(scan_ends: &[u32]) -> Result<usize, HnsWalletError> {
    if scan_ends.is_empty() {
        return Err(HnsWalletError::InvalidLookahead);
    }
    let count = scan_ends.iter().try_fold(0_usize, |count, scan_end| {
        if *scan_end >= MAX_RESTORE_LOOKAHEAD {
            return Err(HnsWalletError::ScanCapacityExhausted);
        }
        let branch = usize::try_from(*scan_end)
            .map_err(|_| HnsWalletError::ScanCapacityExhausted)?
            .checked_add(1)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
        count
            .checked_add(branch)
            .ok_or(HnsWalletError::ScanCapacityExhausted)
    })?;
    if count == 0 || count > MAX_RESTORE_SCRIPTS_PER_QUERY {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    Ok(count)
}

fn derive_restore_addresses(
    store: &WalletStore,
    account: &HnsAccountRecord,
    role: KeyRole,
) -> Result<Vec<DerivedHnsAddress>, HnsWalletError> {
    let branches = match role {
        KeyRole::HnsCoin => vec![
            (0, account.external_scan_end),
            (1, account.internal_scan_end),
        ],
        KeyRole::HnsName => vec![(0, account.name_scan_end)],
        _ => return Err(HnsWalletError::InvalidEvidence),
    };
    let scan_ends: Vec<u32> = branches.iter().map(|(_, scan_end)| *scan_end).collect();
    let address_count = checked_scan_address_count(&scan_ends)?;
    let mut addresses = Vec::with_capacity(address_count);
    for (change, scan_end) in branches {
        for index in 0..=scan_end {
            let derivation = DerivationReference {
                role,
                account: account_number(account),
                change,
                index,
            };
            let id = derived_address_record_id(&account.config, derivation)?;
            let persisted = store.derived_address::<DerivedHnsAddress>(&id)?;
            let public_key = derive_hns_public_key(store, account.config.wallet_id, derivation)?;
            let program = public_key_hash(&public_key)?.to_vec();
            let derived = DerivedHnsAddress {
                account_id: account.config.account_id,
                derivation,
                address: receive_address(account.config.network, &public_key)?,
                program,
                used: persisted
                    .as_ref()
                    .is_some_and(|address| address.value.used),
            };
            if let Some(persisted) = persisted
                && (persisted.id != id
                    || persisted.value.account_id != derived.account_id
                    || persisted.value.derivation != derived.derivation
                    || persisted.value.address != derived.address
                    || persisted.value.program != derived.program)
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            addresses.push(derived);
        }
    }
    Ok(addresses)
}

fn validate_disjoint_restore_programs(
    coin_addresses: &[DerivedHnsAddress],
    name_addresses: &[DerivedHnsAddress],
) -> Result<(), HnsWalletError> {
    let combined = coin_addresses
        .len()
        .checked_add(name_addresses.len())
        .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    if combined == 0 || combined > MAX_RESTORE_ADDRESS_RECORDS {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut programs = BTreeSet::new();
    for address in coin_addresses.iter().chain(name_addresses) {
        restore_derivation_key(address.derivation)?;
        if address.program.len() != 20 || !programs.insert(address.program.clone()) {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn validate_same_restore_snapshot(
    expected_binding: SnapshotBinding,
    expected_mempool: MempoolSnapshotBinding,
    actual_binding: SnapshotBinding,
    actual_mempool: MempoolSnapshotBinding,
) -> Result<(), HnsWalletError> {
    if actual_binding != expected_binding || actual_mempool != expected_mempool {
        Err(HnsWalletError::StaleNodeSnapshot)
    } else {
        Ok(())
    }
}

fn append_restore_branch(
    addresses: &mut Vec<DerivedHnsAddress>,
    history: &mut Vec<HistoryEntry>,
    indexed_coins: &mut Vec<IndexedWalletCoin>,
    branch_addresses: Vec<DerivedHnsAddress>,
    mut branch_history: Vec<HistoryEntry>,
    mut branch_coins: Vec<IndexedWalletCoin>,
) -> Result<(), HnsWalletError> {
    if branch_addresses.is_empty()
        || branch_addresses.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || addresses
            .len()
            .checked_add(branch_addresses.len())
            .is_none_or(|count| count > MAX_RESTORE_ADDRESS_RECORDS)
        || history
            .len()
            .checked_add(branch_history.len())
            .is_none_or(|count| count > MAX_HISTORY_RESULTS)
        || indexed_coins
            .len()
            .checked_add(branch_coins.len())
            .is_none_or(|count| count > MAX_WALLET_COINS)
    {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let offset = u32::try_from(addresses.len())
        .map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    for entry in &mut branch_history {
        if entry.script_index as usize >= branch_addresses.len() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = entry
            .script_index
            .checked_add(offset)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    }
    for coin in &mut branch_coins {
        if coin.script_index as usize >= branch_addresses.len() {
            return Err(HnsWalletError::InvalidEvidence);
        }
        coin.script_index = coin
            .script_index
            .checked_add(offset)
            .ok_or(HnsWalletError::ScanCapacityExhausted)?;
    }
    addresses.extend(branch_addresses);
    history.extend(branch_history);
    indexed_coins.extend(branch_coins);
    Ok(())
}

fn sorted_restore_scripts(
    addresses: &[DerivedHnsAddress],
) -> Result<(Vec<WalletAddressKey>, Vec<u32>), HnsWalletError> {
    if addresses.is_empty() || addresses.len() > MAX_RESTORE_SCRIPTS_PER_QUERY {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut indexed: Vec<(WalletAddressKey, u32)> = addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            u32::try_from(index)
                .map(|index| {
                    (
                        WalletAddressKey {
                            version: 0,
                            hash: address.program.clone(),
                        },
                        index,
                    )
                })
                .map_err(|_| HnsWalletError::ScanCapacityExhausted)
        })
        .collect::<Result<_, _>>()?;
    indexed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    if indexed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let scripts = indexed.iter().map(|(script, _)| script.clone()).collect();
    let remap = indexed.into_iter().map(|(_, index)| index).collect();
    Ok((scripts, remap))
}

fn load_wallet_snapshot<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
    expected_tip: ChainTip,
    expected_binding: Option<SnapshotBinding>,
    expected_mempool: Option<MempoolSnapshotBinding>,
) -> Result<
    (
        SnapshotBinding,
        MempoolSnapshotBinding,
        Vec<HistoryEntry>,
        Vec<IndexedWalletCoin>,
    ),
    HnsWalletError,
> {
    for attempt in 0..MAX_SNAPSHOT_RESTARTS {
        match load_wallet_snapshot_once(
            backend,
            scripts,
            index_remap,
            expected_tip,
            expected_binding,
            expected_mempool,
        ) {
            Err(HnsWalletError::StaleNodeSnapshot) if attempt + 1 < MAX_SNAPSHOT_RESTARTS => {}
            result => return result,
        }
    }
    Err(HnsWalletError::StaleNodeSnapshot)
}

fn load_wallet_snapshot_once<B: HnsBackend>(
    backend: &B,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
    expected_tip: ChainTip,
    expected_binding: Option<SnapshotBinding>,
    expected_mempool: Option<MempoolSnapshotBinding>,
) -> Result<
    (
        SnapshotBinding,
        MempoolSnapshotBinding,
        Vec<HistoryEntry>,
        Vec<IndexedWalletCoin>,
    ),
    HnsWalletError,
> {
    if scripts.is_empty()
        || scripts.len() != index_remap.len()
        || scripts.len() > MAX_RESTORE_SCRIPTS_PER_QUERY
        || !scripts.windows(2).all(|pair| pair[0] < pair[1])
        || scripts
            .iter()
            .any(|script| script.version != 0 || script.hash.len() != 20)
    {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let limit =
        u32::try_from(MAX_SCAN_PAGE_RESULTS).map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    let mut confirmed_cursor: Option<Vec<u8>> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut binding = expected_binding;
    let mut history = Vec::new();
    let mut utxos = Vec::new();
    for _ in 0..MAX_SCAN_PAGES {
        let page = backend.get_confirmed_wallet_page(ConfirmedWalletPageRequest {
            scripts,
            expected_tip,
            expected_epoch: binding.map(|value: SnapshotBinding| value.chain_epoch),
            cursor: confirmed_cursor.as_deref(),
            limit,
        })?;
        if page.binding.tip != expected_tip
            || binding.is_some_and(|expected| expected != page.binding)
            || page
                .history
                .len()
                .saturating_add(page.utxos.len())
                > MAX_SCAN_PAGE_RESULTS
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        binding = Some(page.binding);
        append_remapped_history(&mut history, page.history, index_remap, true)?;
        append_remapped_utxos(&mut utxos, page.utxos, scripts, index_remap)?;
        confirmed_cursor = validated_next_cursor(page.next_cursor, &mut seen_cursors)?;
        if confirmed_cursor.is_none() {
            break;
        }
    }
    if confirmed_cursor.is_some() {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let binding = binding.ok_or(HnsWalletError::InvalidEvidence)?;

    let mut mempool_cursor: Option<Vec<u8>> = None;
    let mut mempool_binding = expected_mempool;
    let mempool_limit = u32::try_from(MAX_MEMPOOL_SCAN_RESULTS)
        .map_err(|_| HnsWalletError::ScanCapacityExhausted)?;
    seen_cursors.clear();
    for _ in 0..MAX_SCAN_PAGES {
        let page = backend.get_mempool_wallet_page(MempoolWalletPageRequest {
            scripts,
            binding,
            expected_mempool: mempool_binding,
            cursor: mempool_cursor.as_deref(),
            limit: mempool_limit,
        })?;
        if page.binding != binding
            || page.mempool.instance_nonce == [0; 32]
            || mempool_binding.is_some_and(|expected| expected != page.mempool)
            || page.history.len() > MAX_HISTORY_RESULTS
        {
            return Err(HnsWalletError::StaleNodeSnapshot);
        }
        mempool_binding = Some(page.mempool);
        append_remapped_history(&mut history, page.history, index_remap, false)?;
        mempool_cursor = validated_next_cursor(page.next_cursor, &mut seen_cursors)?;
        if mempool_cursor.is_none() {
            break;
        }
    }
    if mempool_cursor.is_some() {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mempool_binding = mempool_binding.ok_or(HnsWalletError::InvalidEvidence)?;
    Ok((
        binding,
        mempool_binding,
        bounded_history(history, index_remap.len())?,
        utxos,
    ))
}

fn validated_next_cursor(
    cursor: Option<Vec<u8>>,
    seen: &mut BTreeSet<Vec<u8>>,
) -> Result<Option<Vec<u8>>, HnsWalletError> {
    match cursor {
        Some(cursor)
            if cursor.is_empty()
                || cursor.len() > MAX_SCAN_CURSOR_BYTES
                || !seen.insert(cursor.clone()) =>
        {
            Err(HnsWalletError::StaleNodeSnapshot)
        }
        value => Ok(value),
    }
}

fn append_remapped_history(
    output: &mut Vec<HistoryEntry>,
    entries: Vec<HistoryEntry>,
    index_remap: &[u32],
    confirmed: bool,
) -> Result<(), HnsWalletError> {
    if output.len().saturating_add(entries.len()) > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    for mut entry in entries {
        if confirmed
            != (entry.height.is_some()
                && entry.block_hash.is_some()
                && entry.transaction_position.is_some())
            || (!confirmed
                && (entry.height.is_some()
                    || entry.block_hash.is_some()
                    || entry.transaction_position.is_some()
                    || entry.first_seen_unix.is_none()))
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = *index_remap
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        output.push(entry);
    }
    Ok(())
}

fn append_remapped_utxos(
    output: &mut Vec<IndexedWalletCoin>,
    entries: Vec<IndexedWalletCoin>,
    scripts: &[WalletAddressKey],
    index_remap: &[u32],
) -> Result<(), HnsWalletError> {
    if output.len().saturating_add(entries.len()) > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    for mut entry in entries {
        let expected_script = scripts
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if &entry.output_address != expected_script {
            return Err(HnsWalletError::InvalidEvidence);
        }
        entry.script_index = *index_remap
            .get(entry.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        output.push(entry);
    }
    Ok(())
}

fn validate_spend_evidence(
    evidence: &OutpointSpendEvidence,
    binding: SnapshotBinding,
    expected_outpoints: &[HnsOutpoint],
) -> Result<(), HnsWalletError> {
    if evidence.binding != binding || evidence.entries.len() != expected_outpoints.len() {
        return Err(HnsWalletError::StaleNodeSnapshot);
    }
    for (entry, expected) in evidence.entries.iter().zip(expected_outpoints) {
        if entry.outpoint != *expected
            || entry.spending.is_some_and(|spending| {
                spending.height > binding.tip.height
                    || spending.block_hash == [0; 32]
            })
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(())
}

fn has_competing_spender_in_batches<B: HnsBackend>(
    backend: &B,
    outpoints: &[HnsOutpoint],
    binding: SnapshotBinding,
    expected_spender: TransactionHash,
) -> Result<bool, HnsWalletError> {
    let mut competing = false;
    for batch in outpoints.chunks(MAX_OUTPOINT_SPEND_BATCH) {
        let evidence = backend.get_outpoint_spend_evidence(batch, binding)?;
        validate_spend_evidence(&evidence, binding, batch)?;
        competing |= evidence.entries.iter().any(|entry| {
            entry
                .spending
                .is_some_and(|spending| spending.transaction != expected_spender)
        });
    }
    Ok(competing)
}

fn public_key_hash(public_key: &[u8; 33]) -> Result<[u8; 20], HnsWalletError> {
    let mut hasher = Blake2bVar::new(20).map_err(|_| HnsWalletError::KeyDerivation)?;
    BlakeUpdate::update(&mut hasher, public_key);
    let mut output = [0_u8; 20];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| HnsWalletError::KeyDerivation)?;
    Ok(output)
}

fn bounded_history(
    history: Vec<HistoryEntry>,
    script_count: usize,
) -> Result<Vec<HistoryEntry>, HnsWalletError> {
    if history.len() > MAX_HISTORY_RESULTS {
        return Err(HnsWalletError::HistoryLimit);
    }
    let mut unique = BTreeMap::new();
    for entry in history {
        if entry.script_index as usize >= script_count {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let key = (entry.txid, entry.script_index);
        if let Some(previous) = unique.insert(key, entry.clone())
            && previous != entry
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
    }
    Ok(unique.into_values().collect())
}

fn coalesce_transaction_history(
    history: &[HistoryEntry],
) -> Result<Vec<HistoryEntry>, HnsWalletError> {
    let mut transactions = BTreeMap::new();
    for entry in history {
        match transactions.get_mut(&entry.txid) {
            Some(previous) => {
                if previous.height != entry.height
                    || previous.block_hash != entry.block_hash
                    || previous.transaction_position != entry.transaction_position
                    || previous.first_seen_unix != entry.first_seen_unix
                {
                    return Err(HnsWalletError::InvalidEvidence);
                }
                previous.spent |= entry.spent;
                previous.script_index = previous.script_index.min(entry.script_index);
            }
            None => {
                transactions.insert(entry.txid, entry.clone());
            }
        }
    }
    Ok(transactions.into_values().collect())
}

fn reconcile_coins(
    indexed: Vec<IndexedWalletCoin>,
    addresses: &[DerivedHnsAddress],
) -> Result<Vec<TrackedHnsCoin>, HnsWalletError> {
    if indexed.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidAmount);
    }
    let mut outpoints = BTreeSet::new();
    let mut coins = Vec::with_capacity(indexed.len());
    for indexed_coin in indexed {
        if !outpoints.insert(indexed_coin.coin.outpoint) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let address = addresses
            .get(indexed_coin.script_index as usize)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        if indexed_coin.coin.value.is_zero()
            || indexed_coin.output_address.version != 0
            || indexed_coin.output_address.hash.as_slice() != address.program.as_slice()
            || restore_derivation_key(address.derivation).is_err()
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        coins.push(TrackedHnsCoin {
            coin: indexed_coin.coin,
            derivation: address.derivation,
            address_program: address.program.clone(),
        });
    }
    coins.sort_by_key(|coin| coin.coin.outpoint);
    Ok(coins)
}

const fn is_ordinary_hns_derivation(derivation: DerivationReference) -> bool {
    matches!(derivation.role, KeyRole::HnsCoin)
}

fn is_ordinary_hns_spend_candidate(coin: &TrackedHnsCoin) -> bool {
    is_ordinary_hns_derivation(coin.derivation)
        && !coin.coin.name_locked
        && !coin.coin.coinbase
}

fn decode_transaction_for_id(
    raw: &[u8],
    expected: TransactionHash,
) -> Result<Transaction, HnsWalletError> {
    let transaction = Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidEvidence)?;
    let actual = transaction
        .transaction_hash()
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if actual.as_bytes() != expected.as_bytes() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(transaction)
}

fn validate_inclusion(
    entry: &HistoryEntry,
    status: TransactionStatus,
    inclusion: Option<TransactionInclusion>,
    tip: ChainTip,
    observed_in_current_history: bool,
) -> Result<(), HnsWalletError> {
    if status.conflicted && (status.in_mempool || status.confirmation_count > 0) {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match inclusion {
        Some(inclusion) => {
            if inclusion.height > tip.height
                || (observed_in_current_history && entry.height != Some(inclusion.height))
                || (observed_in_current_history
                    && entry.block_hash != Some(inclusion.block_hash))
                || (observed_in_current_history
                    && inclusion.transaction_index.is_some()
                    && entry.transaction_position != inclusion.transaction_index)
                || status.confirmation_count == 0
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
            let expected_confirmations = tip.height - inclusion.height + 1;
            if u64::from(status.confirmation_count) != expected_confirmations {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
        None => {
            if (observed_in_current_history && entry.height.is_some())
                || status.confirmation_count > 0
            {
                return Err(HnsWalletError::InvalidEvidence);
            }
        }
    }
    Ok(())
}

fn transaction_value_effect<B: HnsBackend>(
    backend: &B,
    transaction: &Transaction,
    programs: &BTreeSet<Vec<u8>>,
    raw_cache: &mut BTreeMap<TransactionHash, Transaction>,
    persisted_raw: &BTreeMap<TransactionHash, Vec<u8>>,
    binding: SnapshotBinding,
    mempool_binding: MempoolSnapshotBinding,
) -> Result<(SignedBaseUnits, Option<BaseUnits>), HnsWalletError> {
    if transaction.inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let mut received = 0_u128;
    let mut sent = 0_u128;
    let mut total_inputs = 0_u128;
    let mut all_inputs_known = true;
    for output in &transaction.outputs {
        if output.address.version == 0 && programs.contains(&output.address.hash) {
            received = received
                .checked_add(u128::from(output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)?;
        }
    }
    for input in &transaction.inputs {
        if input.previous_output.is_null() {
            all_inputs_known = false;
            continue;
        }
        let parent_id = TransactionHash::new(input.previous_output.transaction_hash.into_bytes());
        if !raw_cache.contains_key(&parent_id) {
            let evidence = backend.get_transaction_evidence(
                parent_id,
                binding,
                Some(mempool_binding),
            )?;
            if evidence.binding != binding || evidence.mempool != mempool_binding {
                return Err(HnsWalletError::StaleNodeSnapshot);
            }
            let raw = match evidence.raw {
                Some(raw) => raw,
                None => match persisted_raw.get(&parent_id) {
                    Some(raw) => raw.clone(),
                    None => {
                        all_inputs_known = false;
                        continue;
                    }
                },
            };
            let parent = decode_transaction_for_id(&raw, parent_id)?;
            raw_cache.insert(parent_id, parent);
        }
        let parent = raw_cache
            .get(&parent_id)
            .ok_or(HnsWalletError::InvalidEvidence)?;
        let Some(previous_output) = parent.outputs.get(input.previous_output.index as usize) else {
            return Err(HnsWalletError::InvalidEvidence);
        };
        total_inputs = total_inputs
            .checked_add(u128::from(previous_output.value.get()))
            .ok_or(HnsWalletError::Arithmetic)?;
        if previous_output.address.version == 0 && programs.contains(&previous_output.address.hash)
        {
            sent = sent
                .checked_add(u128::from(previous_output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)?;
        }
    }
    let (negative, magnitude) = if sent > received {
        (true, sent - received)
    } else {
        (false, received - sent)
    };
    let total_outputs = transaction
        .outputs
        .iter()
        .try_fold(0_u128, |total, output| {
            total
                .checked_add(u128::from(output.value.get()))
                .ok_or(HnsWalletError::Arithmetic)
        })?;
    let fee = if all_inputs_known && total_inputs >= total_outputs {
        Some(BaseUnits::new(total_inputs - total_outputs))
    } else {
        None
    };
    Ok((
        SignedBaseUnits {
            negative,
            magnitude: BaseUnits::new(magnitude),
        },
        fee,
    ))
}

fn persist_reconciled_entities(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    coins: &[TrackedHnsCoin],
    transactions: &[HnsTransactionRecord],
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    let existing_coins = store.hns_utxos::<TrackedHnsCoin>(MAX_HISTORY_RESULTS)?;
    let mut revisions: BTreeMap<Vec<u8>, u64> = existing_coins
        .iter()
        .filter(|entity| entity.id.starts_with(&account_entity_prefix(config)))
        .map(|entity| (entity.id.clone(), entity.revision))
        .collect();
    for coin in coins {
        let id = namespaced_outpoint_id(config, coin.coin.outpoint);
        let revision = revisions.remove(id.as_slice()).unwrap_or(0);
        store.save_hns_utxo(&id, revision, coin, now_unix)?;
    }
    for (id, revision) in revisions {
        store.delete_hns_utxo(&id, revision)?;
    }

    let existing_transactions =
        store.hns_transactions::<HnsTransactionRecord>(MAX_HISTORY_RESULTS)?;
    let mut revisions: BTreeMap<Vec<u8>, u64> = existing_transactions
        .iter()
        .filter(|entity| entity.id.starts_with(&account_entity_prefix(config)))
        .map(|entity| (entity.id.clone(), entity.revision))
        .collect();
    for transaction in transactions {
        let id = namespaced_transaction_id(config, transaction.summary.txid);
        let revision = revisions.remove(id.as_slice()).unwrap_or(0);
        store.save_hns_transaction(&id, revision, transaction, now_unix)?;
    }
    for (id, revision) in revisions {
        store.delete_hns_transaction(&id, revision)?;
    }
    Ok(())
}

fn account_entity_prefix(config: &HnsRuntimeConfig) -> [u8; 32] {
    let mut prefix = [0_u8; 32];
    prefix[..16].copy_from_slice(config.wallet_id.as_bytes());
    prefix[16..].copy_from_slice(config.account_id.as_bytes());
    prefix
}

fn account_entity_id(config: &HnsRuntimeConfig) -> [u8; 32] {
    account_entity_prefix(config)
}

fn recovery_entity_id(config: &HnsRuntimeConfig) -> [u8; 33] {
    let mut id = [0_u8; 33];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32] = 1;
    id
}

fn derived_address_id(config: &HnsRuntimeConfig, change: u32, index: u32) -> [u8; 40] {
    let mut id = [0_u8; 40];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..36].copy_from_slice(&change.to_be_bytes());
    id[36..].copy_from_slice(&index.to_be_bytes());
    id
}

fn name_derived_address_id(
    config: &HnsRuntimeConfig,
    change: u32,
    index: u32,
) -> [u8; 41] {
    let mut id = [0_u8; 41];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32] = HNS_NAME_DERIVATION_TAG;
    id[33..37].copy_from_slice(&change.to_be_bytes());
    id[37..].copy_from_slice(&index.to_be_bytes());
    id
}

fn derived_address_record_id(
    config: &HnsRuntimeConfig,
    derivation: DerivationReference,
) -> Result<Vec<u8>, HnsWalletError> {
    if derivation.account != config.account_derivation_index {
        return Err(HnsWalletError::InvalidEvidence);
    }
    match restore_derivation_key(derivation)? {
        (HNS_COIN_DERIVATION_TAG, change, index) => {
            Ok(derived_address_id(config, change, index).to_vec())
        }
        (HNS_NAME_DERIVATION_TAG, change, index) => {
            Ok(name_derived_address_id(config, change, index).to_vec())
        }
        _ => Err(HnsWalletError::InvalidEvidence),
    }
}

fn namespaced_outpoint_id(config: &HnsRuntimeConfig, outpoint: HnsOutpoint) -> [u8; 68] {
    let mut id = [0_u8; 68];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..64].copy_from_slice(outpoint.transaction.as_bytes());
    id[64..].copy_from_slice(&outpoint.output_index.to_le_bytes());
    id
}

fn namespaced_transaction_id(config: &HnsRuntimeConfig, transaction: TransactionHash) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(transaction.as_bytes());
    id
}

fn namespaced_name_id(config: &HnsRuntimeConfig, name_hash: [u8; 32]) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(&name_hash);
    id
}

fn persist_derived_addresses(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    addresses: &[DerivedHnsAddress],
    now_unix: u64,
) -> Result<(), HnsWalletError> {
    if addresses.is_empty() || addresses.len() > MAX_RESTORE_ADDRESS_RECORDS {
        return Err(HnsWalletError::ScanCapacityExhausted);
    }
    let mut ids = BTreeSet::new();
    let mut programs = BTreeSet::new();
    for address in addresses {
        if address.account_id != config.account_id
            || address.program.len() != 20
            || !programs.insert(address.program.clone())
        {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let id = derived_address_record_id(config, address.derivation)?;
        if !ids.insert(id.clone()) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let existing = store.derived_address::<DerivedHnsAddress>(&id)?;
        if existing.as_ref().is_some_and(|stored| {
            stored.id != id
                || stored.value.account_id != address.account_id
                || stored.value.derivation != address.derivation
                || stored.value.address != address.address
                || stored.value.program != address.program
        }) {
            return Err(HnsWalletError::InvalidEvidence);
        }
        let revision = existing.map_or(0, |stored| stored.revision);
        store.save_derived_address(&id, revision, address, now_unix)?;
    }
    Ok(())
}

fn available_unreserved_coins(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    coins: Vec<TrackedHnsCoin>,
    now_unix: u64,
) -> Result<Vec<TrackedHnsCoin>, HnsWalletError> {
    let reservations = store.input_reservations::<HnsInputReservation>(MAX_WALLET_COINS)?;
    let mut reserved = BTreeSet::new();
    let mut expired = Vec::new();
    for stored in reservations {
        if stored.value.wallet_id != config.wallet_id
            || stored.value.account_id != config.account_id
        {
            continue;
        }
        if stored
            .value
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now_unix)
        {
            expired.push(EntityBatchDelete {
                id: stored.id,
                expected_revision: stored.revision,
            });
        } else {
            reserved.insert(stored.value.outpoint);
        }
    }
    if !expired.is_empty() {
        store.apply_entity_batch::<HnsInputReservation>(
            EntityKind::InputReservation,
            &[],
            &expired,
        )?;
    }
    Ok(coins
        .into_iter()
        .filter(|coin| {
            is_ordinary_hns_derivation(coin.derivation)
                && !reserved.contains(&coin.coin.outpoint)
        })
        .collect())
}

fn reservation_saves(
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    inputs: &[TrackedHnsCoin],
    expires_at_unix: u64,
    now_unix: u64,
) -> Result<Vec<EntityBatchSave<HnsInputReservation>>, HnsWalletError> {
    let mut saves = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !is_ordinary_hns_derivation(input.derivation) {
            return Err(HnsWalletError::InvalidWorkflow);
        }
        let reservation = HnsInputReservation {
            wallet_id: config.wallet_id,
            account_id: config.account_id,
            outpoint: input.coin.outpoint,
            workflow_id,
            expires_at_unix: Some(expires_at_unix),
        };
        saves.push(EntityBatchSave {
            id: namespaced_outpoint_id(config, input.coin.outpoint).to_vec(),
            expected_revision: 0,
            value: reservation,
            updated_at_unix: now_unix,
        });
    }
    Ok(saves)
}

fn validate_prepared_reservations(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    outpoints: &[HnsOutpoint],
    expires_at_unix: u64,
) -> Result<(), HnsWalletError> {
    if outpoints.is_empty() || outpoints.len() > MAX_WALLET_COINS {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let expected: BTreeSet<HnsOutpoint> = outpoints.iter().copied().collect();
    if expected.len() != outpoints.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    let reservations = store.input_reservations::<HnsInputReservation>(MAX_WALLET_COINS)?;
    let matching: Vec<_> = reservations
        .into_iter()
        .filter(|stored| {
            stored.value.wallet_id == config.wallet_id
                && stored.value.account_id == config.account_id
                && stored.value.workflow_id == workflow_id
        })
        .collect();
    if matching.len() != expected.len() {
        return Err(HnsWalletError::InvalidWorkflow);
    }
    for stored in matching {
        let expected_id = namespaced_outpoint_id(config, stored.value.outpoint);
        if !expected.contains(&stored.value.outpoint)
            || stored.id.as_slice() != expected_id.as_slice()
            || stored.value.expires_at_unix != Some(expires_at_unix)
        {
            return Err(HnsWalletError::InvalidWorkflow);
        }
    }
    Ok(())
}

fn reservation_activation_saves(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
    now_unix: u64,
) -> Result<Vec<EntityBatchSave<HnsInputReservation>>, HnsWalletError> {
    let reservations = store.input_reservations::<HnsInputReservation>(MAX_WALLET_COINS)?;
    let mut saves = Vec::new();
    for stored in reservations {
        if stored.value.wallet_id != config.wallet_id
            || stored.value.account_id != config.account_id
            || stored.value.workflow_id != workflow_id
        {
            continue;
        }
        let mut reservation = stored.value;
        reservation.expires_at_unix = None;
        saves.push(EntityBatchSave {
            id: stored.id,
            expected_revision: stored.revision,
            value: reservation,
            updated_at_unix: now_unix,
        });
    }
    Ok(saves)
}

fn reservation_deletes(
    store: &WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
) -> Result<Vec<EntityBatchDelete>, HnsWalletError> {
    let reservations = store.input_reservations::<HnsInputReservation>(MAX_WALLET_COINS)?;
    let mut deletes = Vec::new();
    for stored in reservations {
        if stored.value.wallet_id == config.wallet_id
            && stored.value.account_id == config.account_id
            && stored.value.workflow_id == workflow_id
        {
            deletes.push(EntityBatchDelete {
                id: stored.id,
                expected_revision: stored.revision,
            });
        }
    }
    Ok(deletes)
}

fn release_reservations(
    store: &mut WalletStore,
    config: &HnsRuntimeConfig,
    workflow_id: WorkflowId,
) -> Result<(), HnsWalletError> {
    let deletes = reservation_deletes(store, config, workflow_id)?;
    if !deletes.is_empty() {
        store.apply_entity_batch::<HnsInputReservation>(
            EntityKind::InputReservation,
            &[],
            &deletes,
        )?;
    }
    Ok(())
}

impl<B: HnsBackend, C: HnsClock> ChainModule for HnsWalletRuntime<B, C> {
    fn module_id(&self) -> ModuleId {
        ModuleId::Handshake
    }

    fn capabilities(&self) -> ChainCapabilities {
        let config = self
            .cache_read()
            .map(|cache| cache.account.config.clone())
            .ok();
        ChainCapabilities {
            receive: true,
            send: config.as_ref().is_some_and(|config| {
                HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                    && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                    && config.value_operations_enabled
            }),
            history: true,
            atomic_settlement: config.as_ref().is_some_and(|config| {
                HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                    && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                    && config.settlement_enabled
            }),
            hash_algorithm: HashAlgorithm::Sha256,
            locktime_model: LocktimeModel::BlockHeight,
            finality_model: FinalityModel::ProofOfWorkConfirmations,
            fee_model: FeeModel::WeightRate,
        }
    }

    fn sync_status(&self) -> SyncStatus {
        self.cache_read().map_or(
            SyncStatus {
                phase: SyncPhase::Degraded,
                validated_height: 0,
                scanned_height: 0,
                target_height: None,
                last_error: Some("wallet runtime lock is unavailable".to_owned()),
            },
            |cache| cache.sync.clone(),
        )
    }

    fn balance(&self) -> Result<Amount, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        let total = cache
            .coins
            .iter()
            .try_fold(BaseUnits::ZERO, |total, coin| {
                if !is_ordinary_hns_spend_candidate(coin) {
                    Ok(total)
                } else {
                    total
                        .checked_add(coin.coin.value)
                        .map_err(|_| ChainError::Overflow)
                }
            })?;
        Ok(Amount {
            asset: WalletAsset::Hns,
            base_units: total,
        })
    }

    fn transaction_history(&self) -> Result<Vec<TransactionSummary>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        Ok(cache
            .transactions
            .iter()
            .map(|record| record.summary.clone())
            .collect())
    }

    fn receive_target(&self) -> Result<ReceiveTarget, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        let account = cache.account.clone();
        drop(cache);
        let derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 0,
            index: account.next_receive_index,
        };
        let public_key = derive_hns_public_key(
            &self.store_lock().map_err(map_chain_error)?,
            account.config.wallet_id,
            derivation,
        )
        .map_err(map_chain_error)?;
        Ok(ReceiveTarget {
            module: ModuleId::Handshake,
            account: account.config.account_id,
            display: receive_address(account.config.network, &public_key)
                .map_err(map_chain_error)?,
            derivation_index: derivation.index,
        })
    }

    fn prepare_send(&self, request: SendRequest) -> Result<PreparedSend, ChainError> {
        request.validate()?;
        if request.request_nonce == 0
            || request.amount.asset != WalletAsset::Hns
            || request.maximum_fee.is_zero()
        {
            return Err(ChainError::InvalidRequest("invalid Handshake send terms"));
        }
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        if !cache.account.config.value_operations_enabled {
            return Err(ChainError::Disabled);
        }
        if request.account != cache.account.config.account_id {
            return Err(ChainError::InvalidRequest("account does not match runtime"));
        }
        let account = cache.account.clone();
        let account_revision = cache.account_revision;
        let coins = cache.coins.clone();
        drop(cache);
        let workflow_id = send_workflow_id(&account.config, request.request_nonce);
        let mut store = self.store_lock().map_err(map_chain_error)?;
        if let Some(stored) = store
            .load_workflow::<HnsSendWorkflow>(workflow_id)
            .map_err(map_chain_error)?
        {
            let prepared =
                Self::recover_prepared_send(&stored, &request, &account.config, workflow_id, now)?;
            let outpoints: Vec<HnsOutpoint> = stored
                .state
                .plan
                .inputs
                .iter()
                .map(|input| input.coin.outpoint)
                .collect();
            validate_prepared_reservations(
                &store,
                &account.config,
                workflow_id,
                &outpoints,
                stored.state.plan.expires_at_unix,
            )
            .map_err(map_chain_error)?;
            let committed_account = store
                .wallet_account::<HnsAccountRecord>(&account_entity_id(&account.config))
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            self.install_loaded_account(committed_account)
                .map_err(map_chain_error)?;
            return Ok(prepared);
        }
        let coins = available_unreserved_coins(&mut store, &account.config, coins, now)
            .map_err(map_chain_error)?;
        let destination = decode_hns_address(account.config.network, &request.destination)
            .map_err(map_chain_error)?;
        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let change_public =
            derive_hns_public_key(&store, account.config.wallet_id, change_derivation)
                .map_err(map_chain_error)?;
        let change = Address::new(
            0,
            public_key_hash(&change_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidRequest("invalid change address"))?;
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let (transaction, selected, fee) = build_unsigned_payment(
            coins,
            destination,
            change,
            request.amount.base_units,
            fee_rate,
            request.maximum_fee,
            account.config.dust_threshold,
        )
        .map_err(map_chain_error)?;
        let expires_at_unix = now
            .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
            .ok_or(ChainError::Overflow)?;
        let plan = HnsSpendPlan {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            request_nonce: request.request_nonce,
            unsigned_transaction: transaction
                .encode()
                .map_err(|_| ChainError::InvalidTransactionSize)?,
            inputs: selected,
            amount: request.amount.base_units,
            fee,
            maximum_fee: request.maximum_fee,
            destination: request.destination.clone(),
            expires_at_unix,
        };
        let workflow = HnsSendWorkflow {
            plan: plan.clone(),
            stage: HnsSendStage::Prepared,
            transaction: None,
            signed_transaction: None,
            fee_quote: None,
        };
        let reservation_saves = reservation_saves(
            &account.config,
            workflow_id,
            &workflow.plan.inputs,
            expires_at_unix,
            now,
        )
        .map_err(map_chain_error)?;
        let account_save =
            Self::change_account_save(&account, account_revision, change_derivation.index, now)
                .map_err(map_chain_error)?;
        let prepared = Self::prepared_send_from_plan(&plan)?;
        let (_, next_account_revision) = store
            .save_workflow_with_account_and_entity_batch(
                workflow_id,
                WorkflowKind::HnsSend,
                0,
                &workflow,
                false,
                now,
                &account_save,
                EntityKind::InputReservation,
                &reservation_saves,
                &[],
            )
            .map_err(map_chain_error)?;
        self.install_committed_account(account_revision, next_account_revision, account_save.value)
            .map_err(map_chain_error)?;
        Ok(prepared)
    }

    fn authorize_send(&self, request: AuthorizeSend) -> Result<AuthorizedSend, ChainError> {
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        if request.prepared.module != ModuleId::Handshake
            || now > request.prepared.expires_at_unix
            || request.approved_at_unix > now
        {
            return Err(ChainError::ApprovalRequired);
        }
        let plan: HnsSpendPlan =
            serde_json::from_slice(request.prepared.authorization_commitment())
                .map_err(|_| ChainError::InvalidRequest("invalid prepared Handshake send"))?;
        if plan.expires_at_unix != request.prepared.expires_at_unix
            || plan.amount != request.prepared.amount.base_units
            || plan.fee != request.prepared.fee
            || plan.destination != request.prepared.destination
        {
            return Err(ChainError::InvalidRequest("prepared send mismatch"));
        }
        let account = self.cache_read().map_err(map_chain_error)?.account.clone();
        if plan.wallet_id != account.config.wallet_id
            || plan.account_id != account.config.account_id
        {
            return Err(ChainError::InvalidEvidence);
        }
        let (pending_approval, signed, txid) = {
            let store = self.store_lock().map_err(map_chain_error)?;
            let pending_approval = store
                .get_pending_approval(request.approval_id, now)
                .map_err(map_chain_error)?
                .ok_or(ChainError::ApprovalRequired)?;
            let approved: HnsSendApproval =
                serde_json::from_slice(&pending_approval.request_json)
                    .map_err(|_| ChainError::ApprovalRequired)?;
            let commitment: [u8; 32] =
                Sha256::digest(request.prepared.authorization_commitment()).into();
            if approved.workflow_id != plan.workflow_id || approved.commitment != commitment {
                return Err(ChainError::ApprovalRequired);
            }
            let stored = store
                .load_workflow::<HnsSendWorkflow>(plan.workflow_id)
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            if stored.state.plan != plan
                || stored.state.stage != HnsSendStage::Prepared
                || stored.state.transaction.is_some()
                || stored.state.signed_transaction.is_some()
                || stored.state.fee_quote.is_some()
            {
                return Err(ChainError::InvalidEvidence);
            }
            let signed = sign_payment_plan(&store, &account, &plan).map_err(map_chain_error)?;
            let transaction =
                validate_signed_payment_plan(&plan, &signed).map_err(map_chain_error)?;
            let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
            (pending_approval, signed, txid)
        };
        let quote = self
            .quote_final_transaction(&signed, plan.fee, plan.maximum_fee)
            .map_err(map_chain_error)?;
        let commit_now = self.clock.now_unix().map_err(map_chain_error)?;
        if commit_now >= plan.expires_at_unix {
            return Err(ChainError::ApprovalRequired);
        }
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let stored = store
            .load_workflow::<HnsSendWorkflow>(plan.workflow_id)
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?;
        if stored.state.plan != plan
            || stored.state.stage != HnsSendStage::Prepared
            || stored.state.transaction.is_some()
            || stored.state.signed_transaction.is_some()
            || stored.state.fee_quote.is_some()
        {
            return Err(ChainError::InvalidEvidence);
        }
        let workflow = HnsSendWorkflow {
            plan,
            stage: HnsSendStage::Authorized,
            transaction: Some(txid),
            signed_transaction: Some(signed.clone()),
            fee_quote: Some(quote),
        };
        let reservation_saves =
            reservation_activation_saves(
                &store,
                &account.config,
                workflow.plan.workflow_id,
                commit_now,
            )
            .map_err(map_chain_error)?;
        let committed = store
            .consume_approval_and_save_workflow_with_entity_batch(
                &pending_approval,
                commit_now,
                workflow.plan.workflow_id,
                WorkflowKind::HnsSend,
                stored.revision,
                &workflow,
                true,
                EntityKind::InputReservation,
                &reservation_saves,
                &[],
            )
            .map_err(map_chain_error)?;
        if committed.is_none() {
            return Err(ChainError::ApprovalRequired);
        }
        AuthorizedSend::new(ModuleId::Handshake, request.approval_id, signed)
    }

    fn broadcast_send(&self, request: BroadcastSend) -> Result<BroadcastReceipt, ChainError> {
        let raw = request.into_transaction();
        let transaction =
            Transaction::decode(&raw).map_err(|_| ChainError::InvalidTransactionSize)?;
        let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
        let stored = {
            let store = self.store_lock().map_err(map_chain_error)?;
            let workflows = store
                .list_workflows::<HnsSendWorkflow>(WorkflowKind::HnsSend, MAX_HISTORY_RESULTS)
                .map_err(map_chain_error)?;
            let stored = workflows
                .into_iter()
                .find(|workflow| {
                    workflow.state.transaction == Some(txid)
                        && workflow.state.signed_transaction.as_deref() == Some(raw.as_slice())
                })
                .ok_or(ChainError::InvalidEvidence)?;
            if stored.state.stage != HnsSendStage::Authorized {
                return Err(ChainError::InvalidEvidence);
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(ChainError::InvalidEvidence)?;
            validate_final_fee_quote(
                &raw,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.plan.fee,
                stored.state.plan.maximum_fee,
            )
            .map_err(map_chain_error)?;
            stored
        };
        let raw = stored
            .state
            .signed_transaction
            .clone()
            .ok_or(ChainError::InvalidEvidence)?;
        let quote = self
            .quote_final_transaction(
                &raw,
                stored.state.plan.fee,
                stored.state.plan.maximum_fee,
            )
            .map_err(map_chain_error)?;
        let submission_started_at = self.clock.now_unix().map_err(map_chain_error)?;
        let (submission_revision, submission_state) = {
            let mut store = self.store_lock().map_err(map_chain_error)?;
            let current = store
                .load_workflow::<HnsSendWorkflow>(stored.id)
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            if current.revision != stored.revision || current.state != stored.state {
                return Err(ChainError::InvalidEvidence);
            }
            let mut state = current.state;
            state.stage = HnsSendStage::RequiresRebroadcast;
            state.fee_quote = Some(quote);
            let revision = store
                .save_workflow(
                    stored.id,
                    WorkflowKind::HnsSend,
                    current.revision,
                    &state,
                    true,
                    submission_started_at,
                )
                .map_err(map_chain_error)?;
            (revision, state)
        };
        let accepted = self
            .backend
            .broadcast_transaction(&raw)
            .map_err(map_chain_error)?;
        if accepted != txid {
            return Err(ChainError::InvalidEvidence);
        }
        let accepted_at = self.clock.now_unix().map_err(map_chain_error)?;
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let current = store
            .load_workflow::<HnsSendWorkflow>(stored.id)
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?;
        if current.revision != submission_revision || current.state != submission_state {
            return Err(ChainError::InvalidEvidence);
        }
        let mut state = current.state;
        state.stage = HnsSendStage::Broadcast;
        store
            .save_workflow(
                stored.id,
                WorkflowKind::HnsSend,
                current.revision,
                &state,
                true,
                accepted_at,
            )
            .map_err(map_chain_error)?;
        Ok(BroadcastReceipt {
            module: ModuleId::Handshake,
            txid,
            accepted_at_unix: accepted_at,
        })
    }
}

impl<B: HnsBackend, C: HnsClock> UtxoChainModule for HnsWalletRuntime<B, C> {
    fn list_utxos(&self) -> Result<Vec<Utxo>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_ready(&cache)?;
        Ok(cache
            .coins
            .iter()
            .map(|coin| Utxo {
                txid: coin.coin.outpoint.transaction,
                output_index: coin.coin.outpoint.output_index,
                value: Amount {
                    asset: WalletAsset::Hns,
                    base_units: coin.coin.value,
                },
                confirmation_count: coin.coin.confirmation_count,
                spendable: is_ordinary_hns_spend_candidate(coin),
            })
            .collect())
    }

    fn fee_policy(&self) -> Result<UtxoFeePolicy, ChainError> {
        let rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let dust = self
            .cache_read()
            .map_err(map_chain_error)?
            .account
            .config
            .dust_threshold;
        Ok(UtxoFeePolicy {
            base_units_per_kweight: rate,
            minimum_relay: rate,
            dust_threshold: dust,
        })
    }

    fn prepare_htlc_lock(&self, request: HtlcLockRequest) -> Result<PreparedHtlcLock, ChainError> {
        self.prepare_lock(SettlementLockRequest {
            session_id: request.session_id,
            module: ModuleId::Handshake,
            amount: request.amount,
            hashlock: request.hashlock,
            receiver: hex::encode(request.receiver_key),
            refund_target: hex::encode(request.refund_key),
            absolute_timelock: request.absolute_timelock,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcLock(prepared.0))
    }

    fn verify_htlc_lock(
        &self,
        request: VerifyHtlcLockRequest,
    ) -> Result<VerifiedHtlcLock, ChainError> {
        self.verify_lock(VerifySettlementLockRequest {
            expected: request.expected,
            transaction_or_receipt: request.funding_transaction,
            confirmation_count: request.confirmation_count,
        })
        .map(|verified| VerifiedHtlcLock(verified.0))
    }

    fn prepare_htlc_redeem(
        &self,
        request: HtlcRedeemRequest,
    ) -> Result<PreparedHtlcRedeem, ChainError> {
        self.prepare_redeem(SettlementRedeemRequest {
            session_id: request.session_id,
            lock: request.lock,
            preimage: request.preimage,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcRedeem(prepared.0))
    }

    fn prepare_htlc_refund(
        &self,
        request: HtlcRefundRequest,
    ) -> Result<PreparedHtlcRefund, ChainError> {
        self.prepare_refund(SettlementRefundRequest {
            session_id: request.session_id,
            lock: request.lock,
            current_chain_time: request.current_chain_time,
            maximum_fee: request.maximum_fee,
        })
        .map(|prepared| PreparedHtlcRefund(prepared.0))
    }

    fn observe_preimage(
        &self,
        request: ObservePreimageRequest,
    ) -> Result<Option<Preimage>, ChainError> {
        self.observe_secret(request)
    }
}

impl<B: HnsBackend, C: HnsClock> AtomicSettlement for HnsWalletRuntime<B, C> {
    fn settlement_capabilities(&self) -> SettlementCapabilities {
        let enabled = self.cache_read().is_ok_and(|cache| {
            HNS_VALUE_RUNTIME_RELEASE_QUALIFIED
                && HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED
                && cache.account.config.settlement_enabled
        });
        let minimum_confirmations = self
            .cache_read()
            .map_or(0, |cache| cache.account.config.minimum_confirmations);
        SettlementCapabilities {
            module: ModuleId::Handshake,
            supported: enabled,
            minimum_confirmations,
            maximum_lock_bytes: 256,
        }
    }

    fn prepare_lock(
        &self,
        request: SettlementLockRequest,
    ) -> Result<PreparedSettlementLock, ChainError> {
        validate_settlement_request(&request)?;
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let account = cache.account.clone();
        let coins = cache.coins.clone();
        drop(cache);
        let workflow_id = settlement_workflow_id(
            &account.config,
            request.session_id,
            HnsSettlementAction::Lock,
        );
        let mut store = self.store_lock().map_err(map_chain_error)?;
        if let Some(stored) = store
            .load_workflow::<HnsPreparedSettlement>(workflow_id)
            .map_err(map_chain_error)?
        {
            let expected_terms = HnsSettlementTerms::Lock {
                request: request.clone(),
            };
            if stored.kind != settlement_workflow_kind(HnsSettlementAction::Lock)
                || stored.state.wallet_id != account.config.wallet_id
                || stored.state.account_id != account.config.account_id
                || stored.state.workflow_id != workflow_id
                || stored.state.session_id != request.session_id
                || stored.state.action != HnsSettlementAction::Lock
                || stored.state.stage != HnsSettlementStage::Prepared
                || stored.state.terms != expected_terms
                || stored.state.maximum_fee != request.maximum_fee
                || stored.state.fee > stored.state.maximum_fee
                || stored.state.expires_at_unix <= now
            {
                return Err(ChainError::InvalidRequest(
                    "persisted Handshake settlement does not match retry",
                ));
            }
            let prior_quote = stored
                .state
                .fee_quote
                .as_ref()
                .ok_or(ChainError::InvalidEvidence)?;
            validate_final_fee_quote(
                &stored.state.signed_transaction,
                prior_quote,
                prior_quote.binding,
                prior_quote.mempool,
                stored.state.fee,
                stored.state.maximum_fee,
            )
            .map_err(map_chain_error)?;
            let artifact =
                Self::prepared_settlement_artifact(&stored.state).map_err(map_chain_error)?;
            let transaction = Transaction::decode(&stored.state.signed_transaction)
                .map_err(|_| ChainError::InvalidEvidence)?;
            let outpoints: Vec<HnsOutpoint> = transaction
                .inputs
                .iter()
                .map(|input| {
                    if input.previous_output.is_null() {
                        return Err(ChainError::InvalidEvidence);
                    }
                    Ok(HnsOutpoint {
                        transaction: TransactionHash::new(
                            input.previous_output.transaction_hash.into_bytes(),
                        ),
                        output_index: input.previous_output.index,
                    })
                })
                .collect::<Result<_, _>>()?;
            validate_prepared_reservations(
                &store,
                &account.config,
                workflow_id,
                &outpoints,
                stored.state.expires_at_unix,
            )
            .map_err(map_chain_error)?;
            let committed_account = store
                .wallet_account::<HnsAccountRecord>(&account_entity_id(&account.config))
                .map_err(map_chain_error)?
                .ok_or(ChainError::InvalidEvidence)?;
            self.install_loaded_account(committed_account)
                .map_err(map_chain_error)?;
            return Ok(PreparedSettlementLock(artifact));
        }
        let receiver = decode_compressed_key(&request.receiver)?;
        let refund = decode_compressed_key(&request.refund_target)?;
        let script = hns_htlc_script(
            request.hashlock,
            &receiver,
            &refund,
            request.absolute_timelock,
        )?;
        let lock_address = Address::new(0, Sha3_256::digest(&script).to_vec())
            .map_err(|_| ChainError::InvalidRequest("invalid Handshake HTLC address"))?;
        let change_derivation = DerivationReference {
            role: KeyRole::HnsCoin,
            account: account_number(&account),
            change: 1,
            index: account.next_change_index,
        };
        let coins = available_unreserved_coins(&mut store, &account.config, coins, now)
            .map_err(map_chain_error)?;
        let change_public =
            derive_hns_public_key(&store, account.config.wallet_id, change_derivation)
                .map_err(map_chain_error)?;
        let change = Address::new(
            0,
            public_key_hash(&change_public)
                .map_err(map_chain_error)?
                .to_vec(),
        )
        .map_err(|_| ChainError::InvalidRequest("invalid change address"))?;
        let fee_rate = self.backend.estimate_fee_rate(6).map_err(map_chain_error)?;
        let (transaction, selected, fee) = build_unsigned_payment(
            coins,
            lock_address,
            change,
            request.amount.base_units,
            fee_rate,
            request.maximum_fee,
            account.config.dust_threshold,
        )
        .map_err(map_chain_error)?;
        let plan = HnsSpendPlan {
            wallet_id: account.config.wallet_id,
            account_id: account.config.account_id,
            workflow_id,
            request_nonce: 0,
            unsigned_transaction: transaction
                .encode()
                .map_err(|_| ChainError::InvalidTransactionSize)?,
            inputs: selected,
            amount: request.amount.base_units,
            fee,
            maximum_fee: request.maximum_fee,
            destination: hex::encode(Sha3_256::digest(&script)),
            expires_at_unix: now
                .checked_add(PREPARED_ARTIFACT_LIFETIME_SECONDS)
                .ok_or(ChainError::Overflow)?,
        };
        let reservation_saves = reservation_saves(
            &account.config,
            workflow_id,
            &plan.inputs,
            plan.expires_at_unix,
            now,
        )
        .map_err(map_chain_error)?;
        let signed = sign_payment_plan(&store, &account, &plan).map_err(map_chain_error)?;
        validate_signed_payment_plan(&plan, &signed).map_err(map_chain_error)?;
        drop(store);
        let quote = self
            .quote_final_transaction(&signed, fee, request.maximum_fee)
            .map_err(map_chain_error)?;
        let cache = self.cache_read().map_err(map_chain_error)?;
        if cache.account != account {
            return Err(ChainError::InvalidEvidence);
        }
        let account_revision = cache.account_revision;
        drop(cache);
        let account_save =
            Self::change_account_save(&account, account_revision, change_derivation.index, now)
                .map_err(map_chain_error)?;
        let artifact = self
            .persist_prepared_settlement(
                request.session_id,
                HnsSettlementAction::Lock,
                signed,
                fee,
                request.maximum_fee,
                quote,
                HnsSettlementTerms::Lock {
                    request: request.clone(),
                },
                &reservation_saves,
                Some(&account_save),
                now,
            )
            .map_err(map_chain_error)?;
        Ok(PreparedSettlementLock(artifact))
    }

    fn verify_lock(
        &self,
        request: VerifySettlementLockRequest,
    ) -> Result<VerifiedSettlementLock, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let configured_minimum = cache.account.config.minimum_confirmations;
        let binding = cache.binding.ok_or(ChainError::NotSynchronized)?;
        let mempool_binding = cache
            .mempool_binding
            .ok_or(ChainError::NotSynchronized)?;
        let config = cache.account.config.clone();
        drop(cache);
        if request.expected.module != ModuleId::Handshake
            || request.expected.amount.asset != WalletAsset::Hns
            || request.expected.absolute_timelock == 0
            || request.expected.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
            || request.expected.minimum_confirmations < configured_minimum
            || request.confirmation_count < request.expected.minimum_confirmations
            || request.confirmation_count < configured_minimum
        {
            return Err(ChainError::InvalidEvidence);
        }
        let receiver = decode_compressed_key(&request.expected.receiver)?;
        let refund = decode_compressed_key(&request.expected.refund_target)?;
        let script = hns_htlc_script(
            request.expected.hashlock,
            &receiver,
            &refund,
            request.expected.absolute_timelock,
        )?;
        let program = Sha3_256::digest(&script).to_vec();
        let transaction = Transaction::decode(&request.transaction_or_receipt)
            .map_err(|_| ChainError::InvalidEvidence)?;
        let txid = wallet_transaction_hash(&transaction).map_err(map_chain_error)?;
        let evidence = self
            .backend
            .get_transaction_evidence(txid, binding, Some(mempool_binding))
            .map_err(map_chain_error)?;
        if evidence.binding != binding
            || evidence.mempool != mempool_binding
            || evidence.raw.as_deref() != Some(request.transaction_or_receipt.as_slice())
        {
            return Err(ChainError::InvalidEvidence);
        }
        let status = evidence.status;
        if status.conflicted || status.confirmation_count != request.confirmation_count {
            return Err(ChainError::InvalidEvidence);
        }
        let inclusion = evidence.inclusion.ok_or(ChainError::InvalidEvidence)?;
        if inclusion.height > binding.tip.height
            || u64::from(status.confirmation_count) != binding.tip.height - inclusion.height + 1
        {
            return Err(ChainError::InvalidEvidence);
        }
        let amount = u64::try_from(request.expected.amount.base_units.get())
            .map_err(|_| ChainError::InvalidEvidence)?;
        let matches: Vec<usize> = transaction
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, output)| {
                output.value.get() == amount
                    && output.address.version == 0
                    && output.address.hash == program
                    && output.covenant == Covenant::default()
            })
            .map(|(index, _)| index)
            .collect();
        if matches.len() != 1 {
            return Err(ChainError::InvalidEvidence);
        }
        let output_index = u32::try_from(matches[0]).map_err(|_| ChainError::InvalidEvidence)?;
        let terms =
            serde_json::to_vec(&request.expected).map_err(|_| ChainError::InvalidEvidence)?;
        let mut evidence_hasher = Sha256::new();
        evidence_hasher.update(b"hns-wallet-rs/hns-verified-lock/v1");
        evidence_hasher.update(&request.transaction_or_receipt);
        evidence_hasher.update(inclusion.block_hash);
        evidence_hasher.update(inclusion.height.to_be_bytes());
        evidence_hasher.update(output_index.to_be_bytes());
        evidence_hasher.update(
            u64::try_from(terms.len())
                .map_err(|_| ChainError::InvalidEvidence)?
                .to_be_bytes(),
        );
        evidence_hasher.update(&terms);
        evidence_hasher.update(&script);
        let evidence_hash: [u8; 32] = evidence_hasher.finalize().into();
        let verified = VerifiedLock {
            module: ModuleId::Handshake,
            session_id: request.expected.session_id,
            funding_id: txid,
            amount: request.expected.amount,
            hashlock: request.expected.hashlock,
            absolute_timelock: request.expected.absolute_timelock,
            confirmation_count: request.confirmation_count,
            evidence_hash: ObjectHash::new(evidence_hash),
        };
        let record = HnsVerifiedSettlementRecord {
            expected: request.expected,
            verified: verified.clone(),
            output_index,
            script,
        };
        let now = self.clock.now_unix().map_err(map_chain_error)?;
        let mut store = self.store_lock().map_err(map_chain_error)?;
        let id = settlement_entity_id(&config, record.expected.session_id);
        match store
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&id)
            .map_err(map_chain_error)?
        {
            Some(stored) if stored.value == record => {
                return Ok(VerifiedSettlementLock(stored.value.verified));
            }
            Some(stored)
                if same_verified_settlement_binding(&stored.value, &record)
                    && record.verified.confirmation_count
                        >= stored.value.verified.confirmation_count =>
            {
                store
                    .save_hns_verified_settlement(&id, stored.revision, &record, now)
                    .map_err(map_chain_error)?;
            }
            Some(_) => return Err(ChainError::InvalidEvidence),
            None => {
                store
                    .save_hns_verified_settlement(&id, 0, &record, now)
                    .map_err(map_chain_error)?;
            }
        }
        Ok(VerifiedSettlementLock(verified))
    }

    fn prepare_redeem(
        &self,
        request: SettlementRedeemRequest,
    ) -> Result<PreparedSettlementRedeem, ChainError> {
        let expected_hash: [u8; 32] =
            Sha256::digest(request.preimage.expose_for_settlement()).into();
        if expected_hash != *request.lock.hashlock.as_bytes() {
            return Err(ChainError::InvalidEvidence);
        }
        self.prepare_settlement_spend(
            request.session_id,
            request.lock,
            Some(request.preimage),
            request.maximum_fee,
            None,
            HnsSettlementAction::Redeem,
        )
        .map(PreparedSettlementRedeem)
    }

    fn prepare_refund(
        &self,
        request: SettlementRefundRequest,
    ) -> Result<PreparedSettlementRefund, ChainError> {
        if request.current_chain_time >= HNS_LOCKTIME_THRESHOLD
            || request.lock.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
            || request.current_chain_time < request.lock.absolute_timelock
        {
            return Err(ChainError::InvalidRequest("refund timelock is not mature"));
        }
        self.prepare_settlement_spend(
            request.session_id,
            request.lock,
            None,
            request.maximum_fee,
            Some(request.current_chain_time),
            HnsSettlementAction::Refund,
        )
        .map(PreparedSettlementRefund)
    }

    fn observe_secret(
        &self,
        request: ObserveSecretRequest,
    ) -> Result<Option<Preimage>, ChainError> {
        let cache = self.cache_read().map_err(map_chain_error)?;
        ensure_settlement_ready(&cache)?;
        let binding = cache.binding.ok_or(ChainError::NotSynchronized)?;
        let mempool_binding = cache
            .mempool_binding
            .ok_or(ChainError::NotSynchronized)?;
        let config = cache.account.config.clone();
        drop(cache);
        let record = self
            .store_lock()
            .map_err(map_chain_error)?
            .hns_verified_settlement::<HnsVerifiedSettlementRecord>(&settlement_entity_id(
                &config,
                request.session_id,
            ))
            .map_err(map_chain_error)?
            .ok_or(ChainError::InvalidEvidence)?
            .value;
        if record.expected.session_id != request.session_id
            || record.expected.hashlock != request.hashlock
        {
            return Err(ChainError::InvalidEvidence);
        }
        let evidence = self
            .backend
            .get_transaction_evidence(
                request.spending_transaction,
                binding,
                Some(mempool_binding),
            )
            .map_err(map_chain_error)?;
        if evidence.binding != binding || evidence.mempool != mempool_binding {
            return Err(ChainError::InvalidEvidence);
        }
        let status = evidence.status;
        if status.conflicted || (!status.in_mempool && status.confirmation_count == 0) {
            return Ok(None);
        }
        let raw = evidence.raw.ok_or(ChainError::InvalidEvidence)?;
        let transaction = decode_transaction_for_id(&raw, request.spending_transaction)
            .map_err(map_chain_error)?;
        let expected_outpoint = Outpoint {
            transaction_hash: CanonicalTransactionHash::new(
                record.verified.funding_id.into_bytes(),
            ),
            index: record.output_index,
        };
        let mut matching_input = None;
        for input in &transaction.inputs {
            if input.previous_output != expected_outpoint {
                continue;
            }
            if matching_input.replace(input).is_some() {
                return Err(ChainError::InvalidEvidence);
            }
        }
        let Some(input) = matching_input else {
            return Err(ChainError::InvalidEvidence);
        };
        if input.witness.items.len() != 4
            || input.witness.items[0].len() != 65
            || input.witness.items[1].len() != Preimage::LENGTH
            || input.witness.items[2].is_empty()
            || input.witness.items[3] != record.script
        {
            return Err(ChainError::InvalidEvidence);
        }
        let digest: [u8; 32] = Sha256::digest(&input.witness.items[1]).into();
        if digest != *record.expected.hashlock.as_bytes() {
            return Err(ChainError::InvalidEvidence);
        }
        let bytes: [u8; 32] = input.witness.items[1]
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidEvidence)?;
        Ok(Some(Preimage::new(bytes)))
    }
}

fn ensure_ready(cache: &HnsRuntimeCache) -> Result<(), ChainError> {
    if cache.sync.phase == SyncPhase::Ready
        && cache.sync.validated_height == cache.sync.scanned_height
    {
        Ok(())
    } else {
        Err(ChainError::NotSynchronized)
    }
}

fn map_chain_error(error: HnsWalletError) -> ChainError {
    match error {
        HnsWalletError::StoreLocked | HnsWalletError::MissingSeed => ChainError::Locked,
        HnsWalletError::MainnetDisabled | HnsWalletError::RuntimeIntegrationUnavailable => {
            ChainError::Disabled
        }
        HnsWalletError::InvalidAmount
        | HnsWalletError::InvalidAddress
        | HnsWalletError::InvalidPreparedArtifact
        | HnsWalletError::PreparedArtifactExpired
        | HnsWalletError::InvalidRuntimeConfiguration => {
            ChainError::InvalidRequest("invalid Handshake wallet request")
        }
        HnsWalletError::Arithmetic => ChainError::Overflow,
        HnsWalletError::FeeLimit => ChainError::FeeLimit,
        HnsWalletError::InsufficientFunds => {
            ChainError::InvalidRequest("insufficient Handshake funds")
        }
        HnsWalletError::InvalidEvidence
        | HnsWalletError::NameNotOwned
        | HnsWalletError::StaleNodeSnapshot
        | HnsWalletError::FeeQuoteInputUnavailable
        | HnsWalletError::InvalidFeeQuoteTransaction
        | HnsWalletError::InvalidFeeQuote => ChainError::InvalidEvidence,
        HnsWalletError::Store => ChainError::Backend("wallet store failed".to_owned()),
        _ => ChainError::Backend("Handshake wallet runtime failed".to_owned()),
    }
}

fn validate_final_fee_quote(
    raw: &[u8],
    quote: &HnsTransactionFeeQuote,
    binding: SnapshotBinding,
    mempool: MempoolSnapshotBinding,
    expected_fee: BaseUnits,
    maximum_fee: BaseUnits,
) -> Result<(), HnsWalletError> {
    let transaction =
        Transaction::decode(raw).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != raw
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let txid = wallet_transaction_hash(&transaction)?;
    let weight = transaction
        .weight()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if maximum_fee.is_zero()
        || expected_fee > maximum_fee
        || quote.txid != txid
        || quote.binding != binding
        || quote.mempool != mempool
        || quote.target_blocks != DEFAULT_FEE_TARGET_BLOCKS
        || quote.transaction_weight != weight
        || quote.transaction_weight == 0
        || quote.sigop_adjusted_policy_vbytes == 0
        || quote.rate_atomic_units_per_1000_policy_vbytes == 0
        || quote.actual_fee != expected_fee
        || quote.minimum_policy_fee > quote.actual_fee
        || !quote.meets_minimum_policy_fee
        || !quote.minimum_policy_fee_shortfall.is_zero()
    {
        return Err(HnsWalletError::InvalidFeeQuote);
    }
    match quote.rate_source {
        HnsFeeRateSource::MinimumRelay if quote.rate_sample_count == 0 => {}
        HnsFeeRateSource::Mempool if quote.rate_sample_count > 0 => {}
        _ => return Err(HnsWalletError::InvalidFeeQuote),
    }
    if !HNS_FEE_QUOTE_ALGEBRA_RELEASE_QUALIFIED {
        return Err(HnsWalletError::RuntimeIntegrationUnavailable);
    }
    Ok(())
}

fn validate_witness_only_change(
    unsigned: &Transaction,
    signed_raw: &[u8],
) -> Result<Transaction, HnsWalletError> {
    let signed =
        Transaction::decode(signed_raw).map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if signed
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?
        != signed_raw
        || unsigned.version != signed.version
        || unsigned.outputs != signed.outputs
        || unsigned.locktime != signed.locktime
        || unsigned.inputs.len() != signed.inputs.len()
        || unsigned
            .inputs
            .iter()
            .zip(&signed.inputs)
            .any(|(left, right)| {
                left.previous_output != right.previous_output || left.sequence != right.sequence
            })
    {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    Ok(signed)
}

fn validate_signed_payment_plan(
    plan: &HnsSpendPlan,
    signed_raw: &[u8],
) -> Result<Transaction, HnsWalletError> {
    let unsigned = Transaction::decode(&plan.unsigned_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    validate_witness_only_change(&unsigned, signed_raw)
}

fn decode_hns_address(network: HnsNetwork, value: &str) -> Result<Address, HnsWalletError> {
    let (hrp, version, program) =
        segwit::decode(value).map_err(|_| HnsWalletError::InvalidAddress)?;
    let expected = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::InvalidAddress)?;
    if hrp != expected {
        return Err(HnsWalletError::InvalidAddress);
    }
    Address::new(version.to_u8(), program).map_err(|_| HnsWalletError::InvalidAddress)
}

fn build_unsigned_payment(
    mut coins: Vec<TrackedHnsCoin>,
    destination: Address,
    change: Address,
    amount: BaseUnits,
    fee_rate: BaseUnits,
    maximum_fee: BaseUnits,
    dust_threshold: BaseUnits,
) -> Result<(Transaction, Vec<TrackedHnsCoin>, BaseUnits), HnsWalletError> {
    let amount = u64::try_from(amount.get()).map_err(|_| HnsWalletError::InvalidAmount)?;
    if amount == 0 || fee_rate.is_zero() || maximum_fee.is_zero() {
        return Err(HnsWalletError::InvalidAmount);
    }
    coins.retain(|coin| {
        is_ordinary_hns_spend_candidate(coin) && coin.coin.confirmation_count > 0
    });
    coins.sort_by(|left, right| {
        left.coin
            .value
            .cmp(&right.coin.value)
            .then_with(|| left.coin.outpoint.cmp(&right.coin.outpoint))
    });
    let mut selected = Vec::new();
    let mut total = 0_u128;
    for coin in coins {
        total = total
            .checked_add(coin.coin.value.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        selected.push(coin);
        let provisional = unsigned_payment_transaction(
            &selected,
            destination.clone(),
            Some((change.clone(), 1)),
            amount,
        )?;
        let change_fee = transaction_fee(&provisional, fee_rate)?;
        let required = u128::from(amount)
            .checked_add(change_fee.get())
            .ok_or(HnsWalletError::Arithmetic)?;
        if total < required {
            continue;
        }
        let change_value = total - required;
        if change_value >= dust_threshold.get() {
            if change_fee > maximum_fee {
                return Err(HnsWalletError::FeeLimit);
            }
            let change_value =
                u64::try_from(change_value).map_err(|_| HnsWalletError::InvalidAmount)?;
            let transaction = unsigned_payment_transaction(
                &selected,
                destination.clone(),
                Some((change.clone(), change_value)),
                amount,
            )?;
            return Ok((transaction, selected, change_fee));
        }

        let no_change = unsigned_payment_transaction(&selected, destination.clone(), None, amount)?;
        let minimum_fee = transaction_fee(&no_change, fee_rate)?;
        let actual_fee = BaseUnits::new(total - u128::from(amount));
        if actual_fee >= minimum_fee && actual_fee <= maximum_fee {
            return Ok((no_change, selected, actual_fee));
        }
    }
    Err(HnsWalletError::InsufficientFunds)
}

fn unsigned_payment_transaction(
    selected: &[TrackedHnsCoin],
    destination: Address,
    change: Option<(Address, u64)>,
    amount: u64,
) -> Result<Transaction, HnsWalletError> {
    let inputs = selected
        .iter()
        .map(|coin| Input {
            previous_output: Outpoint {
                transaction_hash: CanonicalTransactionHash::new(
                    coin.coin.outpoint.transaction.into_bytes(),
                ),
                index: coin.coin.outpoint.output_index,
            },
            sequence: u32::MAX,
            witness: Witness {
                items: vec![vec![0; 65], vec![0; 33]],
            },
        })
        .collect();
    let mut outputs = vec![Output {
        value: Dollarydoos::new(amount),
        address: destination,
        covenant: Covenant::default(),
    }];
    if let Some((address, value)) = change {
        outputs.push(Output {
            value: Dollarydoos::new(value),
            address,
            covenant: Covenant::default(),
        });
    }
    Ok(Transaction {
        version: 0,
        inputs,
        outputs,
        locktime: 0,
    })
}

fn transaction_fee(
    transaction: &Transaction,
    unqualified_node_rate_per_kvb: BaseUnits,
) -> Result<BaseUnits, HnsWalletError> {
    let weight = transaction
        .weight()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    let product = unqualified_node_rate_per_kvb
        .get()
        .checked_mul(weight as u128)
        .ok_or(HnsWalletError::Arithmetic)?;
    let fee = product.checked_add(999).ok_or(HnsWalletError::Arithmetic)? / 1_000;
    Ok(BaseUnits::new(fee))
}

fn sign_payment_plan(
    store: &WalletStore,
    account: &HnsAccountRecord,
    plan: &HnsSpendPlan,
) -> Result<Vec<u8>, HnsWalletError> {
    let mut transaction = Transaction::decode(&plan.unsigned_transaction)
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)?;
    if transaction.inputs.len() != plan.inputs.len() || transaction.inputs.is_empty() {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    for (index, coin) in plan.inputs.iter().enumerate() {
        let expected = Outpoint {
            transaction_hash: CanonicalTransactionHash::new(
                coin.coin.outpoint.transaction.into_bytes(),
            ),
            index: coin.coin.outpoint.output_index,
        };
        if transaction.inputs[index].previous_output != expected
            || coin.derivation.role != KeyRole::HnsCoin
        {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let secret = derive_secret(&seed, coin.derivation)?;
        let signing =
            SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
        let public = signing.verifying_key().to_encoded_point(true);
        let public_bytes: [u8; 33] = public
            .as_bytes()
            .try_into()
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if public_key_hash(&public_bytes)?.as_slice() != coin.address_program {
            return Err(HnsWalletError::InvalidPreparedArtifact);
        }
        let previous_value =
            u64::try_from(coin.coin.value.get()).map_err(|_| HnsWalletError::InvalidAmount)?;
        let script = p2pkh_script(&coin.address_program)?;
        let digest = signature_hash(&transaction, index, &script, previous_value, SIGHASH_ALL)
            .map_err(|_| HnsWalletError::Signing)?;
        let signature: Signature = signing
            .sign_prehash(&digest)
            .map_err(|_| HnsWalletError::Signing)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut encoded = signature.to_bytes().to_vec();
        encoded.push(SIGHASH_ALL as u8);
        transaction.inputs[index].witness = Witness {
            items: vec![encoded, public.as_bytes().to_vec()],
        };
    }
    transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

fn p2pkh_script(program: &[u8]) -> Result<Vec<u8>, HnsWalletError> {
    if program.len() != 20 {
        return Err(HnsWalletError::InvalidPreparedArtifact);
    }
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
    script.extend_from_slice(program);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    Ok(script)
}

fn wallet_transaction_hash(transaction: &Transaction) -> Result<TransactionHash, HnsWalletError> {
    transaction
        .transaction_hash()
        .map(|hash| TransactionHash::new(hash.into_bytes()))
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

fn send_workflow_id(config: &HnsRuntimeConfig, request_nonce: u64) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/hns-send-workflow/v1");
    hasher.update(account_entity_prefix(config));
    hasher.update(request_nonce.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn ensure_settlement_ready(cache: &HnsRuntimeCache) -> Result<(), ChainError> {
    ensure_ready(cache)?;
    if cache.account.config.settlement_enabled {
        Ok(())
    } else {
        Err(ChainError::Disabled)
    }
}

fn validate_settlement_request(request: &SettlementLockRequest) -> Result<(), ChainError> {
    if request.module != ModuleId::Handshake
        || request.amount.asset != WalletAsset::Hns
        || request.amount.base_units.is_zero()
        || request.maximum_fee.is_zero()
        || request.absolute_timelock == 0
        || request.absolute_timelock >= HNS_LOCKTIME_THRESHOLD
    {
        return Err(ChainError::InvalidRequest(
            "invalid Handshake settlement terms",
        ));
    }
    Ok(())
}

fn decode_compressed_key(value: &str) -> Result<[u8; 33], ChainError> {
    let mut key = [0_u8; 33];
    hex::decode_to_slice(value, &mut key)
        .map_err(|_| ChainError::InvalidRequest("invalid compressed settlement key"))?;
    VerifyingKey::from_sec1_bytes(&key)
        .map_err(|_| ChainError::InvalidRequest("invalid compressed settlement key"))?;
    Ok(key)
}

fn hns_htlc_script(
    hashlock: ObjectHash,
    receiver: &[u8; 33],
    refund: &[u8; 33],
    absolute_timelock: u64,
) -> Result<Vec<u8>, ChainError> {
    let timelock = u32::try_from(absolute_timelock)
        .map_err(|_| ChainError::InvalidRequest("Handshake timelock exceeds u32"))?;
    let encoded_timelock = encode_script_number(u64::from(timelock));
    let mut script = Vec::with_capacity(114);
    script.extend_from_slice(&[OP_IF, OP_SHA256, 32]);
    script.extend_from_slice(hashlock.as_bytes());
    script.extend_from_slice(&[OP_EQUALVERIFY, 33]);
    script.extend_from_slice(receiver);
    script.extend_from_slice(&[OP_ELSE, encoded_timelock.len() as u8]);
    script.extend_from_slice(&encoded_timelock);
    script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]);
    script.extend_from_slice(refund);
    script.extend_from_slice(&[OP_ENDIF, OP_CHECKSIG]);
    Ok(script)
}

fn encode_script_number(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut encoded = Vec::new();
    while value > 0 {
        encoded.push(value as u8);
        value >>= 8;
    }
    if encoded.last().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded
}

fn derive_settlement_secret(
    seed: &[u8],
    account: &HnsAccountRecord,
    session_id: SessionId,
    refund: bool,
) -> Result<Zeroizing<[u8; 32]>, HnsWalletError> {
    let mut context = Sha256::new();
    context.update(HNS_SETTLEMENT_KEY_DOMAIN);
    context.update(account_number(account).to_be_bytes());
    context.update(session_id.as_bytes());
    context.update([u8::from(refund)]);
    let context: [u8; 32] = context.finalize().into();
    for counter in 0_u8..=u8::MAX {
        let mut info = Vec::with_capacity(context.len() + 1);
        info.extend_from_slice(&context);
        info.push(counter);
        let hkdf = Hkdf::<Sha256>::new(Some(b"Handshake atomic settlement role"), seed);
        let mut candidate = Zeroizing::new([0_u8; 32]);
        hkdf.expand(&info, candidate.as_mut())
            .map_err(|_| HnsWalletError::KeyDerivation)?;
        if SigningKey::from_slice(candidate.as_slice()).is_ok() {
            return Ok(candidate);
        }
    }
    Err(HnsWalletError::KeyDerivation)
}

fn derive_settlement_public_key(
    store: &WalletStore,
    account: &HnsAccountRecord,
    session_id: SessionId,
    refund: bool,
) -> Result<[u8; 33], HnsWalletError> {
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_settlement_secret(&seed, account, session_id, refund)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    signing
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| HnsWalletError::KeyDerivation)
}

fn settlement_workflow_id(
    config: &HnsRuntimeConfig,
    session_id: SessionId,
    action: HnsSettlementAction,
) -> WorkflowId {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-rs/hns-settlement-workflow/v1");
    hasher.update(account_entity_prefix(config));
    hasher.update(session_id.as_bytes());
    hasher.update([match action {
        HnsSettlementAction::Lock => 0,
        HnsSettlementAction::Redeem => 1,
        HnsSettlementAction::Refund => 2,
    }]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    WorkflowId::new(id)
}

fn settlement_workflow_kind(action: HnsSettlementAction) -> WorkflowKind {
    if action == HnsSettlementAction::Refund {
        WorkflowKind::Refund
    } else {
        WorkflowKind::AtomicSwap
    }
}

fn same_prepared_settlement(
    stored: &HnsPreparedSettlement,
    artifact: &HnsPreparedSettlement,
) -> bool {
    stored.wallet_id == artifact.wallet_id
        && stored.account_id == artifact.account_id
        && stored.workflow_id == artifact.workflow_id
        && stored.session_id == artifact.session_id
        && stored.action == artifact.action
        && artifact.stage == HnsSettlementStage::Prepared
        && stored.transaction == artifact.transaction
        && stored.signed_transaction == artifact.signed_transaction
        && stored.fee == artifact.fee
        && stored.maximum_fee == artifact.maximum_fee
        && stored.expires_at_unix == artifact.expires_at_unix
        && stored.terms == artifact.terms
}

fn same_verified_settlement_binding(
    stored: &HnsVerifiedSettlementRecord,
    candidate: &HnsVerifiedSettlementRecord,
) -> bool {
    stored.expected == candidate.expected
        && stored.output_index == candidate.output_index
        && stored.script == candidate.script
        && stored.verified.module == candidate.verified.module
        && stored.verified.session_id == candidate.verified.session_id
        && stored.verified.funding_id == candidate.verified.funding_id
        && stored.verified.amount == candidate.verified.amount
        && stored.verified.hashlock == candidate.verified.hashlock
        && stored.verified.absolute_timelock == candidate.verified.absolute_timelock
        && stored.verified.evidence_hash == candidate.verified.evidence_hash
}

fn settlement_entity_id(config: &HnsRuntimeConfig, session_id: SessionId) -> [u8; 64] {
    let mut id = [0_u8; 64];
    id[..32].copy_from_slice(&account_entity_prefix(config));
    id[32..].copy_from_slice(session_id.as_bytes());
    id
}

fn sign_htlc_spend(
    store: &WalletStore,
    account: &HnsAccountRecord,
    mut transaction: Transaction,
    session_id: SessionId,
    script: &[u8],
    previous_value: u64,
    preimage: Option<&Preimage>,
    refund: bool,
) -> Result<Vec<u8>, HnsWalletError> {
    let seed = store
        .get_secret(
            account.config.wallet_id.as_bytes(),
            SecretKind::RecoverySeed,
        )?
        .ok_or(HnsWalletError::MissingSeed)?;
    let secret = derive_settlement_secret(&seed, account, session_id, refund)?;
    let signing =
        SigningKey::from_slice(secret.as_slice()).map_err(|_| HnsWalletError::KeyDerivation)?;
    let digest = signature_hash(&transaction, 0, script, previous_value, SIGHASH_ALL)
        .map_err(|_| HnsWalletError::Signing)?;
    let signature: Signature = signing
        .sign_prehash(&digest)
        .map_err(|_| HnsWalletError::Signing)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut encoded = signature.to_bytes().to_vec();
    encoded.push(SIGHASH_ALL as u8);
    transaction.inputs[0].witness = if refund {
        Witness {
            items: vec![encoded, Vec::new(), script.to_vec()],
        }
    } else {
        let preimage = preimage.ok_or(HnsWalletError::InvalidPreparedArtifact)?;
        Witness {
            items: vec![
                encoded,
                preimage.expose_for_settlement().to_vec(),
                vec![1],
                script.to_vec(),
            ],
        }
    };
    transaction
        .encode()
        .map_err(|_| HnsWalletError::InvalidPreparedArtifact)
}

#[derive(Debug, Error)]
pub enum HnsWalletError {
    #[error("wallet store failed")]
    Store,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("wallet recovery seed is unavailable")]
    MissingSeed,
    #[error("key role does not belong to Handshake")]
    WrongKeyRole,
    #[error("deterministic key derivation failed")]
    KeyDerivation,
    #[error("Handshake address encoding failed")]
    Address,
    #[error("invalid Handshake address or network")]
    InvalidAddress,
    #[error("amount or coin count is invalid")]
    InvalidAmount,
    #[error("checked arithmetic failed")]
    Arithmetic,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("fee exceeds the approved maximum")]
    FeeLimit,
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("name proof or ownership evidence is invalid")]
    InvalidEvidence,
    #[error("invalid persisted name workflow")]
    InvalidWorkflow,
    #[error("wallet store must be unlocked")]
    StoreLocked,
    #[error("persisted account configuration does not match")]
    AccountConfigurationMismatch,
    #[error("the HD account component is already assigned in this wallet")]
    DuplicateAccountDerivation,
    #[error("runtime synchronization lock is unavailable")]
    RuntimePoisoned,
    #[error("system clock is unavailable")]
    Clock,
    #[error("restore lookahead or persisted scan progress is invalid")]
    InvalidLookahead,
    #[error("the bounded restore scan cannot preserve a complete trailing gap")]
    ScanCapacityExhausted,
    #[error("the node snapshot, cursor, or mempool generation changed")]
    StaleNodeSnapshot,
    #[error("a fee-quote input is unavailable in the bound node snapshot")]
    FeeQuoteInputUnavailable,
    #[error("the node rejected the transaction as ineligible for a fee quote")]
    InvalidFeeQuoteTransaction,
    #[error("node fee-quote evidence does not match the final transaction")]
    InvalidFeeQuote,
    #[error("the reserved change address was concurrently advanced")]
    StaleAddressReservation,
    #[error("runtime configuration is invalid")]
    InvalidRuntimeConfiguration,
    #[error("mainnet value operations remain disabled by release policy")]
    MainnetDisabled,
    #[error("Handshake value runtime integration has not passed its release gate")]
    RuntimeIntegrationUnavailable,
    #[error("prepared transaction artifact is invalid")]
    InvalidPreparedArtifact,
    #[error("prepared transaction artifact has expired")]
    PreparedArtifactExpired,
    #[error("transaction signing failed")]
    Signing,
    #[error("history result exceeds the configured bound")]
    HistoryLimit,
    #[error("current name owner output is not controlled by this account")]
    NameNotOwned,
    #[error("wallet state encoding failed")]
    Encoding,
    #[error("Handshake backend failed: {0}")]
    Backend(String),
}

impl From<StoreError> for HnsWalletError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

impl From<serde_json::Error> for HnsWalletError {
    fn from(_: serde_json::Error) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime_config() -> HnsRuntimeConfig {
        HnsRuntimeConfig {
            wallet_id: WalletId::new([11; 16]),
            account_id: AccountId::new([12; 16]),
            account_derivation_index: 7,
            network: HnsNetwork::Regtest,
            birthday_height: 100,
            restore_lookahead: DEFAULT_RESTORE_LOOKAHEAD,
            minimum_confirmations: 2,
            dust_threshold: BaseUnits::new(DEFAULT_DUST_THRESHOLD),
            value_operations_enabled: false,
            settlement_enabled: false,
        }
    }

    fn test_derived_address(role: KeyRole, program: u8) -> DerivedHnsAddress {
        let config = test_runtime_config();
        DerivedHnsAddress {
            account_id: config.account_id,
            derivation: DerivationReference {
                role,
                account: config.account_derivation_index,
                change: 0,
                index: 0,
            },
            address: format!("test-address-{program}"),
            program: vec![program; 20],
            used: false,
        }
    }

    fn test_snapshot(epoch: u64) -> SnapshotBinding {
        SnapshotBinding {
            tip: ChainTip {
                height: 500,
                block_hash: [21; 32],
                tree_root: [22; 32],
            },
            chain_epoch: epoch,
        }
    }

    fn test_mempool(generation: u64) -> MempoolSnapshotBinding {
        MempoolSnapshotBinding {
            instance_nonce: [23; 32],
            generation,
        }
    }

    #[test]
    fn authoritative_reconcile_account_rejects_derivation_rollback() {
        let cached = HnsAccountRecord {
            config: test_runtime_config(),
            next_receive_index: 3,
            next_change_index: 4,
            next_name_index: 5,
            external_scan_end: 102,
            internal_scan_end: 103,
            name_scan_end: 104,
            last_used_external: Some(2),
            last_used_internal: Some(3),
            last_used_name: Some(4),
        };
        assert!(validate_authoritative_reconcile_account(&cached, 7, &cached, 7).is_ok());

        let mut advanced = cached.clone();
        advanced.next_change_index = 5;
        advanced.internal_scan_end = 104;
        assert!(validate_authoritative_reconcile_account(&cached, 7, &advanced, 8).is_ok());

        let mut rolled_back = advanced.clone();
        rolled_back.next_receive_index = 2;
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &rolled_back, 8),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &advanced, 6),
            Err(HnsWalletError::InvalidEvidence)
        ));
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &advanced, 7),
            Err(HnsWalletError::InvalidEvidence)
        ));

        let mut mismatched = advanced;
        mismatched.config.minimum_confirmations += 1;
        assert!(matches!(
            validate_authoritative_reconcile_account(&cached, 7, &mismatched, 8),
            Err(HnsWalletError::AccountConfigurationMismatch)
        ));
    }

    #[test]
    fn legacy_account_state_defaults_the_independent_name_scan() {
        let account = HnsAccountRecord {
            config: test_runtime_config(),
            next_receive_index: 3,
            next_change_index: 4,
            next_name_index: 8,
            external_scan_end: 102,
            internal_scan_end: 103,
            name_scan_end: 107,
            last_used_external: Some(2),
            last_used_internal: Some(3),
            last_used_name: Some(7),
        };
        let mut encoded = serde_json::to_value(account).expect("encode account");
        let object = encoded.as_object_mut().expect("account object");
        object.remove("next_name_index");
        object.remove("name_scan_end");
        object.remove("last_used_name");
        let decoded: HnsAccountRecord =
            serde_json::from_value(encoded).expect("decode legacy account");
        assert_eq!(decoded.next_name_index, 0);
        assert_eq!(decoded.name_scan_end, 0);
        assert_eq!(decoded.last_used_name, None);
        assert_eq!(decoded.next_receive_index, 3);
        assert_eq!(decoded.external_scan_end, 102);
    }

    #[test]
    fn name_address_ids_are_role_discriminated_without_changing_coin_ids() {
        let config = test_runtime_config();
        let coin = DerivationReference {
            role: KeyRole::HnsCoin,
            account: config.account_derivation_index,
            change: 0,
            index: 9,
        };
        let name = DerivationReference {
            role: KeyRole::HnsName,
            ..coin
        };
        let coin_id = derived_address_record_id(&config, coin).expect("coin id");
        let name_id = derived_address_record_id(&config, name).expect("name id");
        assert_eq!(coin_id, derived_address_id(&config, 0, 9).to_vec());
        assert_eq!(coin_id.len(), 40);
        assert_eq!(name_id.len(), 41);
        assert_ne!(coin_id, name_id);
        assert!(derived_address_record_id(
            &config,
            DerivationReference { change: 1, ..name }
        )
        .is_err());
    }

    #[test]
    fn separate_restore_queries_share_one_exact_snapshot() {
        let binding = test_snapshot(4);
        let mempool = test_mempool(5);
        assert!(validate_same_restore_snapshot(binding, mempool, binding, mempool).is_ok());
        assert!(
            validate_same_restore_snapshot(binding, mempool, test_snapshot(6), mempool).is_err()
        );
        assert!(
            validate_same_restore_snapshot(binding, mempool, binding, test_mempool(6)).is_err()
        );
        let restarted = MempoolSnapshotBinding {
            instance_nonce: [24; 32],
            generation: mempool.generation,
        };
        assert!(
            validate_same_restore_snapshot(binding, mempool, binding, restarted).is_err()
        );
    }

    #[test]
    fn name_gap_and_next_index_never_shrink_after_restart_or_reorg() {
        assert_eq!(required_scan_end(None, 500, 100), 500);
        assert_eq!(required_scan_end(Some(3), 500, 100), 500);
        assert_eq!(required_scan_end(Some(550), 500, 100), 650);
        assert_eq!(advance_next_derivation_index(50, None), 50);
        assert_eq!(advance_next_derivation_index(50, Some(3)), 50);
        assert_eq!(advance_next_derivation_index(50, Some(80)), 81);
        assert_eq!(
            checked_scan_address_count(&[4_999, 4_999]).expect("full coin query"),
            MAX_RESTORE_SCRIPTS_PER_QUERY
        );
        assert_eq!(
            checked_scan_address_count(&[9_999]).expect("full name query"),
            MAX_RESTORE_SCRIPTS_PER_QUERY
        );
        assert!(checked_scan_address_count(&[5_000, 5_000]).is_err());
        assert_eq!(
            MAX_RESTORE_ADDRESS_RECORDS,
            MAX_RESTORE_SCRIPTS_PER_QUERY * 2
        );
    }

    #[test]
    fn name_outputs_are_tracked_but_never_ordinary_spend_candidates() {
        let address = test_derived_address(KeyRole::HnsName, 31);
        let tracked = reconcile_coins(
            vec![IndexedWalletCoin {
                coin: WalletCoin {
                    outpoint: HnsOutpoint {
                        transaction: TransactionHash::new([32; 32]),
                        output_index: 1,
                    },
                    value: BaseUnits::new(1_000),
                    confirmation_count: 10,
                    coinbase: false,
                    name_locked: false,
                },
                script_index: 0,
                output_address: WalletAddressKey {
                    version: 0,
                    hash: address.program.clone(),
                },
            }],
            &[address],
        )
        .expect("track name output");
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].derivation.role, KeyRole::HnsName);
        assert!(!is_ordinary_hns_spend_candidate(&tracked[0]));
    }

    #[test]
    fn duplicate_programs_and_unsupported_name_branches_fail_closed() {
        let coin = test_derived_address(KeyRole::HnsCoin, 41);
        let name = test_derived_address(KeyRole::HnsName, 41);
        assert!(validate_disjoint_restore_programs(&[coin], &[name]).is_err());
        assert!(restore_derivation_key(DerivationReference {
            role: KeyRole::HnsName,
            account: 7,
            change: 1,
            index: 0,
        })
        .is_err());
        assert!(restore_derivation_key(DerivationReference {
            role: KeyRole::HnsShakedex,
            account: 7,
            change: 0,
            index: 0,
        })
        .is_err());
    }

    #[test]
    fn coin_selection_excludes_name_locked_outputs_and_is_deterministic() {
        let coins = vec![
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([1; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(7),
                confirmation_count: 1,
                coinbase: false,
                name_locked: true,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([2; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(5),
                confirmation_count: 1,
                coinbase: false,
                name_locked: false,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([3; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(4),
                confirmation_count: 2,
                coinbase: false,
                name_locked: false,
            },
        ];
        let selected = select_coins(&coins, BaseUnits::new(8)).expect("selection");
        assert_eq!(selected.coins.len(), 2);
        assert_eq!(selected.total, BaseUnits::new(9));
        assert_eq!(selected.change, BaseUnits::new(1));
        assert!(
            selected
                .coins
                .iter()
                .all(|coin| !coin.name_locked && !coin.coinbase)
        );
    }

    #[test]
    fn role_separation_changes_public_keys_and_address_networks() {
        let seed = [7_u8; 64];
        let coin = derive_secret(
            &seed,
            DerivationReference {
                role: KeyRole::HnsCoin,
                account: 0,
                change: 0,
                index: 0,
            },
        )
        .expect("coin key");
        let name = derive_secret(
            &seed,
            DerivationReference {
                role: KeyRole::HnsName,
                account: 0,
                change: 0,
                index: 0,
            },
        )
        .expect("name key");
        assert_ne!(*coin, *name);
        let signing = SigningKey::from_slice(coin.as_slice()).expect("signing key");
        let public: [u8; 33] = VerifyingKey::from(&signing)
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key");
        assert!(
            receive_address(HnsNetwork::Mainnet, &public)
                .expect("mainnet")
                .starts_with("hs1")
        );
        assert!(
            receive_address(HnsNetwork::Regtest, &public)
                .expect("regtest")
                .starts_with("rs1")
        );
    }
}
