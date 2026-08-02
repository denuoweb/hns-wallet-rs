#![doc = "Handshake wallet key roles, restoration, UTXO selection, and name workflows."]
#![forbid(unsafe_code)]

use core::fmt;

use bech32::{Hrp, segwit};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use hns_covenants::{hash_name, validate_name};
use hns_primitives::{NameHash, TreeRoot};
use hns_urkel_proof::{ProofKind, UrkelProof};
use hns_wallet_store::{SecretKind, StoreError, WalletStore};
use hns_wallet_types::{
    BaseUnits, DerivationReference, KeyRole, ObjectHash, TransactionHash, WalletId, WorkflowId,
    WorkflowKind,
};
use k256::ecdsa::{SigningKey, VerifyingKey};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HNS_DERIVATION_DOMAIN: &[u8] = b"hns-wallet-rs/hns-role-key/v1";
pub const MAX_RESTORE_LOOKAHEAD: u32 = 10_000;
pub const DEFAULT_RESTORE_LOOKAHEAD: u32 = 100;
pub const MAX_WALLET_COINS: usize = 10_000;
pub const MAX_HISTORY_RESULTS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    let sha = Sha256::digest(compressed_public_key);
    let program = Ripemd160::digest(sha);
    let hrp = Hrp::parse(network.hrp()).map_err(|_| HnsWalletError::Address)?;
    segwit::encode_v0(hrp, &program).map_err(|_| HnsWalletError::Address)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WalletCoin {
    pub outpoint: HnsOutpoint,
    pub value: BaseUnits,
    pub confirmation_count: u32,
    pub name_locked: bool,
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
        .filter(|coin| !coin.name_locked)
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
    fn get_raw_transaction(&self, txid: TransactionHash)
    -> Result<Option<Vec<u8>>, HnsWalletError>;
    fn get_transaction_status(
        &self,
        txid: TransactionHash,
    ) -> Result<TransactionStatus, HnsWalletError>;
    fn get_transaction_inclusion(
        &self,
        txid: TransactionHash,
    ) -> Result<Option<TransactionInclusion>, HnsWalletError>;
    fn get_script_history(&self, scripts: &[Vec<u8>]) -> Result<Vec<HistoryEntry>, HnsWalletError>;
    fn get_script_utxos(&self, scripts: &[Vec<u8>]) -> Result<Vec<WalletCoin>, HnsWalletError>;
    fn get_spending_transaction(
        &self,
        outpoint: HnsOutpoint,
    ) -> Result<Option<TransactionHash>, HnsWalletError>;
    fn broadcast_transaction(&self, raw: &[u8]) -> Result<TransactionHash, HnsWalletError>;
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<BaseUnits, HnsWalletError>;
    fn get_name_state(&self, name_hash: [u8; 32]) -> Result<Option<Vec<u8>>, HnsWalletError>;
    fn get_name_proof(&self, name_hash: [u8; 32]) -> Result<NameProofResponse, HnsWalletError>;
    fn get_name_owner_transaction(
        &self,
        name_hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, HnsWalletError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tree_root: [u8; 32],
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
    pub transaction_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub txid: TransactionHash,
    pub height: Option<u64>,
    pub spent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameProofResponse {
    pub name_hash: [u8; 32],
    pub tree_root: [u8; 32],
    pub proof: Vec<u8>,
    pub proof_height: u64,
    pub raw_resource: Vec<u8>,
    pub owner_outpoint: Option<HnsOutpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KnownName {
    pub name: Vec<u8>,
    pub name_hash: [u8; 32],
    pub proof_height: u64,
    pub owner_outpoint: Option<HnsOutpoint>,
    pub raw_state: Option<Vec<u8>>,
    pub raw_resource: Vec<u8>,
}

pub fn import_known_name<B: HnsBackend>(
    backend: &B,
    name: &[u8],
) -> Result<KnownName, HnsWalletError> {
    if !validate_name(name) {
        return Err(HnsWalletError::InvalidName);
    }
    let name_hash = hash_name(name)
        .map_err(|_| HnsWalletError::InvalidName)?
        .into_bytes();
    let response = backend.get_name_proof(name_hash)?;
    if response.name_hash != name_hash {
        return Err(HnsWalletError::InvalidEvidence);
    }
    let proof = UrkelProof {
        name_hash: NameHash::new(name_hash),
        kind: if response.owner_outpoint.is_some() {
            ProofKind::Inclusion
        } else {
            ProofKind::NonInclusion
        },
        raw: response.proof,
    };
    let raw_state = proof
        .verify_strict(TreeRoot::new(response.tree_root))
        .map_err(|_| HnsWalletError::InvalidEvidence)?;
    if response.owner_outpoint.is_some() != raw_state.is_some() {
        return Err(HnsWalletError::InvalidEvidence);
    }
    Ok(KnownName {
        name: name.to_vec(),
        name_hash,
        proof_height: response.proof_height,
        owner_outpoint: response.owner_outpoint,
        raw_state,
        raw_resource: response.raw_resource,
    })
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
    #[error("amount or coin count is invalid")]
    InvalidAmount,
    #[error("checked arithmetic failed")]
    Arithmetic,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("name proof or ownership evidence is invalid")]
    InvalidEvidence,
    #[error("invalid persisted name workflow")]
    InvalidWorkflow,
    #[error("Handshake backend failed: {0}")]
    Backend(String),
}

impl From<StoreError> for HnsWalletError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                name_locked: true,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([2; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(5),
                confirmation_count: 1,
                name_locked: false,
            },
            WalletCoin {
                outpoint: HnsOutpoint {
                    transaction: TransactionHash::new([3; 32]),
                    output_index: 0,
                },
                value: BaseUnits::new(4),
                confirmation_count: 2,
                name_locked: false,
            },
        ];
        let selected = select_coins(&coins, BaseUnits::new(8)).expect("selection");
        assert_eq!(selected.coins.len(), 2);
        assert_eq!(selected.total, BaseUnits::new(9));
        assert_eq!(selected.change, BaseUnits::new(1));
        assert!(selected.coins.iter().all(|coin| !coin.name_locked));
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
