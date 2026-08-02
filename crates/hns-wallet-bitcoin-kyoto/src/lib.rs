#![doc = "Kyoto-only Bitcoin wallet integration and native HTLC settlement."]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bdk_kyoto::builder::{Builder, BuilderExt};
use bdk_kyoto::{LightClient, ScanType, TrustedPeer, state, wallets};
use bdk_wallet::bitcoin::absolute;
use bdk_wallet::bitcoin::blockdata::opcodes::all::{
    OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256,
};
use bdk_wallet::bitcoin::consensus::{deserialize, serialize};
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
use bdk_wallet::bitcoin::script::Builder as ScriptBuilder;
use bdk_wallet::bitcoin::{
    Address, Amount as BitcoinAmount, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness, bip32::Xpriv, psbt::Psbt, transaction,
};
use bdk_wallet::template::Bip84;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
use bip39::{Language, Mnemonic};
use hns_wallet_types::{
    ChainCapabilities, FeeModel, FinalityModel, HashAlgorithm, LocktimeModel, ObjectHash,
    TransactionHash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MIN_HTLC_DUST_SATS: u64 = 330;
pub const MAX_HTLC_SCRIPT_BYTES: usize = 256;
pub const MAX_BITCOIN_TRANSACTION_BYTES: usize = 400_000;
pub const MAX_REQUIRED_PEERS: u8 = 8;
pub const MAX_RECOVERY_SCRIPT_INDEX: u32 = 100_000;
pub const DEFAULT_REQUIRED_PEERS: u8 = 3;

/// The only production synchronization model exposed by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinSynchronizationModel {
    KyotoBip157DirectP2p,
}

pub const fn synchronization_model() -> BitcoinSynchronizationModel {
    BitcoinSynchronizationModel::KyotoBip157DirectP2p
}

pub const fn capabilities() -> ChainCapabilities {
    ChainCapabilities {
        receive: true,
        send: true,
        history: true,
        atomic_settlement: true,
        hash_algorithm: HashAlgorithm::Sha256,
        locktime_model: LocktimeModel::BlockHeight,
        finality_model: FinalityModel::ProofOfWorkConfirmations,
        fee_model: FeeModel::WeightRate,
    }
}

/// Wallet-owned checkpoint metadata. Kyoto persists validated headers, filter
/// headers, compact filters and peer state in `data_dir`; BDK persists wallet
/// checkpoints, transactions and outputs in the wallet SQLite connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KyotoWalletState {
    pub birthday_height: u32,
    pub validated_height: u32,
    pub scanned_height: u32,
    pub last_consistent_height: u32,
    pub relevant_block_hashes: Vec<[u8; 32]>,
    pub last_started_at_unix: u64,
}

impl KyotoWalletState {
    pub fn new_wallet(validated_height: u32, now_unix: u64) -> Self {
        Self {
            birthday_height: validated_height,
            validated_height,
            scanned_height: validated_height,
            last_consistent_height: validated_height,
            relevant_block_hashes: Vec::new(),
            last_started_at_unix: now_unix,
        }
    }

    pub fn restored_wallet(birthday_height: Option<u32>, now_unix: u64) -> Self {
        let birthday = birthday_height.unwrap_or(0);
        Self {
            birthday_height: birthday,
            validated_height: birthday,
            scanned_height: birthday,
            last_consistent_height: birthday,
            relevant_block_hashes: Vec::new(),
            last_started_at_unix: now_unix,
        }
    }

    pub fn rewind_for_reorg(&mut self, common_ancestor_height: u32) {
        self.validated_height = self.validated_height.min(common_ancestor_height);
        self.scanned_height = self.scanned_height.min(common_ancestor_height);
        self.last_consistent_height = common_ancestor_height;
        self.relevant_block_hashes.truncate(
            usize::try_from(common_ancestor_height.saturating_sub(self.birthday_height))
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
    }
}

#[derive(Clone, Debug)]
pub struct KyotoRuntimeConfig {
    pub network: Network,
    pub data_dir: PathBuf,
    pub required_peers: u8,
    pub response_timeout: Duration,
    pub trusted_peers: Vec<TrustedPeer>,
}

impl KyotoRuntimeConfig {
    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        if self.data_dir.as_os_str().is_empty()
            || self.required_peers == 0
            || self.required_peers > MAX_REQUIRED_PEERS
            || self.response_timeout.is_zero()
        {
            return Err(BitcoinWalletError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Builds the actual direct-P2P Kyoto light client. There is intentionally no
/// alternate production backend or runtime selector.
pub fn build_kyoto_client(
    wallet: &Wallet,
    config: KyotoRuntimeConfig,
    scan_type: ScanType,
) -> Result<LightClient<state::Idle, wallets::Single>, BitcoinWalletError> {
    config.validate()?;
    if wallet.network() != config.network {
        return Err(BitcoinWalletError::NetworkMismatch);
    }
    let mut builder = Builder::new(config.network)
        .data_dir(config.data_dir)
        .required_peers(config.required_peers)
        .response_timeout(config.response_timeout);
    if !config.trusted_peers.is_empty() {
        builder = builder.add_peers(config.trusted_peers);
    }
    builder
        .build_with_wallet(wallet, scan_type)
        .map_err(|error| BitcoinWalletError::Kyoto(error.to_string()))
}

pub fn parse_recovery_phrase(phrase: &str) -> Result<Mnemonic, BitcoinWalletError> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| BitcoinWalletError::InvalidRecoveryPhrase)
}

pub fn create_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
) -> Result<Wallet, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
    Wallet::create(
        Bip84(root, KeychainKind::External),
        Bip84(root, KeychainKind::Internal),
    )
    .network(network)
    .use_spk_cache(true)
    .create_wallet_no_persist()
    .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))
}

/// Creates a BDK descriptor wallet in SQLite. BDK persists public descriptors
/// and chain data; private descriptor keys are extracted into the in-memory
/// signer map and must be reconstructed from the encrypted mnemonic on load.
pub fn create_persisted_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
    connection: &mut bdk_wallet::rusqlite::Connection,
) -> Result<PersistedWallet<bdk_wallet::rusqlite::Connection>, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
    Wallet::create(
        Bip84(root, KeychainKind::External),
        Bip84(root, KeychainKind::Internal),
    )
    .network(network)
    .use_spk_cache(true)
    .create_wallet(connection)
    .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))
}

pub fn load_persisted_descriptor_wallet(
    mnemonic: &Mnemonic,
    network: Network,
    connection: &mut bdk_wallet::rusqlite::Connection,
) -> Result<PersistedWallet<bdk_wallet::rusqlite::Connection>, BitcoinWalletError> {
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let root = Xpriv::new_master(network, seed.as_slice())
        .map_err(|_| BitcoinWalletError::KeyDerivation)?;
    Wallet::load()
        .descriptor(
            KeychainKind::External,
            Some(Bip84(root, KeychainKind::External)),
        )
        .descriptor(
            KeychainKind::Internal,
            Some(Bip84(root, KeychainKind::Internal)),
        )
        .extract_keys()
        .check_network(network)
        .use_spk_cache(true)
        .load_wallet(connection)
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?
        .ok_or(BitcoinWalletError::WalletNotFound)
}

pub fn next_receive_address(wallet: &mut Wallet) -> String {
    wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .to_string()
}

#[derive(Debug)]
pub struct PreparedBitcoinSend {
    pub destination: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    psbt: Psbt,
}

pub fn prepare_native_send(
    wallet: &mut Wallet,
    destination: &str,
    amount_sats: u64,
    fee_rate_sat_vb: u64,
    maximum_fee_sats: u64,
) -> Result<PreparedBitcoinSend, BitcoinWalletError> {
    if amount_sats == 0 || fee_rate_sat_vb == 0 {
        return Err(BitcoinWalletError::InvalidAmount);
    }
    let unchecked =
        Address::from_str(destination).map_err(|_| BitcoinWalletError::InvalidDestination)?;
    let address = unchecked
        .require_network(wallet.network())
        .map_err(|_| BitcoinWalletError::NetworkMismatch)?;
    let fee_rate = bdk_wallet::bitcoin::FeeRate::from_sat_per_vb(fee_rate_sat_vb)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(
            address.script_pubkey(),
            BitcoinAmount::from_sat(amount_sats),
        )
        .fee_rate(fee_rate)
        .only_witness_utxo();
    let psbt = builder
        .finish()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let fee_sats = wallet
        .calculate_fee(&psbt.unsigned_tx)
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?
        .to_sat();
    if fee_sats > maximum_fee_sats {
        return Err(BitcoinWalletError::FeeLimit);
    }
    Ok(PreparedBitcoinSend {
        destination: destination.to_owned(),
        amount_sats,
        fee_sats,
        psbt,
    })
}

/// The caller must bind the approval to the prepared destination, amount, fee
/// and serialized PSBT commitment before invoking this signing boundary.
pub fn authorize_native_send(
    wallet: &Wallet,
    mut prepared: PreparedBitcoinSend,
) -> Result<Vec<u8>, BitcoinWalletError> {
    let finalized = wallet
        .sign(&mut prepared.psbt, SignOptions::default())
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    if !finalized {
        return Err(BitcoinWalletError::SigningIncomplete);
    }
    let transaction = prepared
        .psbt
        .extract_tx()
        .map_err(|error| BitcoinWalletError::Wallet(error.to_string()))?;
    let raw = serialize(&transaction);
    if raw.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    Ok(raw)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BitcoinHtlc {
    pub hashlock: [u8; 32],
    pub receiver_public_key: Vec<u8>,
    pub refund_public_key: Vec<u8>,
    pub refund_height: u32,
    pub witness_script: Vec<u8>,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinHtlc {
    pub fn new(
        hashlock: [u8; 32],
        receiver_public_key: PublicKey,
        refund_public_key: PublicKey,
        refund_height: u32,
    ) -> Result<Self, BitcoinWalletError> {
        if hashlock == [0; 32] || refund_height == 0 {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        let witness_script = ScriptBuilder::new()
            .push_opcode(OP_IF)
            .push_opcode(OP_SHA256)
            .push_slice(hashlock)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&receiver_public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(i64::from(refund_height))
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_key(&refund_public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script();
        if witness_script.len() > MAX_HTLC_SCRIPT_BYTES {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        Ok(Self {
            hashlock,
            receiver_public_key: receiver_public_key.to_bytes(),
            refund_public_key: refund_public_key.to_bytes(),
            refund_height,
            witness_script: witness_script.into_bytes(),
            script_pubkey: script_pubkey.into_bytes(),
        })
    }

    pub fn validate(&self) -> Result<(), BitcoinWalletError> {
        let receiver = PublicKey::from_slice(&self.receiver_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let refund = PublicKey::from_slice(&self.refund_public_key)
            .map_err(|_| BitcoinWalletError::InvalidHtlc)?;
        let expected = Self::new(self.hashlock, receiver, refund, self.refund_height)?;
        if &expected != self {
            return Err(BitcoinWalletError::InvalidHtlc);
        }
        Ok(())
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.script_pubkey.clone())
    }

    pub fn witness_script(&self) -> ScriptBuf {
        ScriptBuf::from_bytes(self.witness_script.clone())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBitcoinLock {
    pub funding_txid: TransactionHash,
    pub output_index: u32,
    pub value_sats: u64,
    pub confirmation_count: u32,
    pub htlc: BitcoinHtlc,
}

pub fn verify_htlc_funding(
    raw_transaction: &[u8],
    htlc: &BitcoinHtlc,
    expected_value_sats: u64,
    confirmation_count: u32,
    minimum_confirmations: u32,
) -> Result<VerifiedBitcoinLock, BitcoinWalletError> {
    if raw_transaction.is_empty() || raw_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    if expected_value_sats < MIN_HTLC_DUST_SATS || confirmation_count < minimum_confirmations {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    htlc.validate()?;
    let transaction: Transaction =
        deserialize(raw_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let expected_script = htlc.script_pubkey();
    let mut matching = transaction.output.iter().enumerate().filter(|(_, output)| {
        output.value.to_sat() == expected_value_sats && output.script_pubkey == expected_script
    });
    let (output_index, _) = matching.next().ok_or(BitcoinWalletError::InvalidEvidence)?;
    if matching.next().is_some() {
        return Err(BitcoinWalletError::AmbiguousEvidence);
    }
    let txid = transaction.compute_txid().to_byte_array();
    Ok(VerifiedBitcoinLock {
        funding_txid: TransactionHash::new(txid),
        output_index: u32::try_from(output_index)
            .map_err(|_| BitcoinWalletError::InvalidEvidence)?,
        value_sats: expected_value_sats,
        confirmation_count,
        htlc: htlc.clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HtlcSpendBranch {
    Redeem,
    Refund,
}

/// Constructs a policy-correct unsigned spend. A chain-specific signer fills
/// the first witness item after the approval boundary.
pub fn prepare_htlc_spend(
    lock: &VerifiedBitcoinLock,
    destination: ScriptBuf,
    fee_sats: u64,
    branch: HtlcSpendBranch,
    preimage: Option<&[u8; 32]>,
    current_height: u32,
) -> Result<Transaction, BitcoinWalletError> {
    if fee_sats == 0 || fee_sats >= lock.value_sats {
        return Err(BitcoinWalletError::InvalidFee);
    }
    let output_value = lock
        .value_sats
        .checked_sub(fee_sats)
        .ok_or(BitcoinWalletError::InvalidFee)?;
    if output_value < MIN_HTLC_DUST_SATS {
        return Err(BitcoinWalletError::Dust);
    }
    let (lock_time, sequence, branch_selector, preimage_item) = match branch {
        HtlcSpendBranch::Redeem => {
            let secret = preimage.ok_or(BitcoinWalletError::MissingPreimage)?;
            if Sha256::digest(secret).as_slice() != lock.htlc.hashlock {
                return Err(BitcoinWalletError::InvalidPreimage);
            }
            (
                absolute::LockTime::ZERO,
                Sequence::MAX,
                vec![1],
                secret.to_vec(),
            )
        }
        HtlcSpendBranch::Refund => {
            if preimage.is_some() || current_height < lock.htlc.refund_height {
                return Err(BitcoinWalletError::TimelockNotReached);
            }
            (
                absolute::LockTime::from_height(lock.htlc.refund_height)
                    .map_err(|_| BitcoinWalletError::InvalidHtlc)?,
                Sequence::ENABLE_LOCKTIME_NO_RBF,
                Vec::new(),
                Vec::new(),
            )
        }
    };
    let outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    let witness = Witness::from_slice(&[
        Vec::new(),
        preimage_item,
        branch_selector,
        lock.htlc.witness_script.clone(),
    ]);
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness,
        }],
        output: vec![TxOut {
            value: BitcoinAmount::from_sat(output_value),
            script_pubkey: destination,
        }],
    })
}

/// Extracts a revealed 32-byte preimage only from a transaction which spends
/// the expected funding output and contains the exact committed witness script.
pub fn observe_preimage(
    raw_spending_transaction: &[u8],
    lock: &VerifiedBitcoinLock,
) -> Result<Option<[u8; 32]>, BitcoinWalletError> {
    if raw_spending_transaction.is_empty()
        || raw_spending_transaction.len() > MAX_BITCOIN_TRANSACTION_BYTES
    {
        return Err(BitcoinWalletError::TransactionTooLarge);
    }
    let transaction: Transaction =
        deserialize(raw_spending_transaction).map_err(|_| BitcoinWalletError::InvalidEvidence)?;
    let expected_outpoint = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_byte_array(lock.funding_txid.into_bytes()),
        vout: lock.output_index,
    };
    let mut matching_inputs = transaction
        .input
        .iter()
        .filter(|input| input.previous_output == expected_outpoint);
    let input = matching_inputs
        .next()
        .ok_or(BitcoinWalletError::InvalidEvidence)?;
    if matching_inputs.next().is_some()
        || input.witness.last() != Some(lock.htlc.witness_script.as_slice())
    {
        return Err(BitcoinWalletError::InvalidEvidence);
    }
    for item in input.witness.iter() {
        if let Ok(candidate) = <[u8; 32]>::try_from(item) {
            let digest: [u8; 32] = sha256::Hash::hash(&candidate).to_byte_array();
            if digest == lock.htlc.hashlock {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

pub fn htlc_commitment(htlc: &BitcoinHtlc) -> ObjectHash {
    let mut hasher = Sha256::new();
    hasher.update(b"hns-wallet-bitcoin-htlc/v1");
    hasher.update(&htlc.witness_script);
    ObjectHash::new(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum BitcoinWalletError {
    #[error("invalid Bitcoin module configuration")]
    InvalidConfiguration,
    #[error("invalid recovery phrase")]
    InvalidRecoveryPhrase,
    #[error("Bitcoin key derivation failed")]
    KeyDerivation,
    #[error("Bitcoin wallet was not found in persistence")]
    WalletNotFound,
    #[error("Bitcoin wallet error: {0}")]
    Wallet(String),
    #[error("Kyoto client error: {0}")]
    Kyoto(String),
    #[error("address or wallet network mismatch")]
    NetworkMismatch,
    #[error("invalid destination")]
    InvalidDestination,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("invalid or excessive fee")]
    InvalidFee,
    #[error("fee exceeds approved maximum")]
    FeeLimit,
    #[error("transaction signing was incomplete")]
    SigningIncomplete,
    #[error("transaction exceeds bounded maximum")]
    TransactionTooLarge,
    #[error("invalid HTLC parameters or script")]
    InvalidHtlc,
    #[error("HTLC output is dust")]
    Dust,
    #[error("required preimage is missing")]
    MissingPreimage,
    #[error("preimage does not match hashlock")]
    InvalidPreimage,
    #[error("refund timelock has not been reached")]
    TimelockNotReached,
    #[error("chain evidence is missing or inconsistent")]
    InvalidEvidence,
    #[error("chain evidence contains multiple possible matches")]
    AmbiguousEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn key(byte: u8) -> PublicKey {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("valid deterministic key");
        PublicKey::new(secret.public_key(&Secp256k1::new()))
    }

    fn htlc() -> BitcoinHtlc {
        let preimage = [9_u8; 32];
        BitcoinHtlc::new(Sha256::digest(preimage).into(), key(3), key(4), 500).expect("valid HTLC")
    }

    fn funding(htlc: &BitcoinHtlc, value: u64) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: BitcoinAmount::from_sat(value),
                script_pubkey: htlc.script_pubkey(),
            }],
        }
    }

    #[test]
    fn key_roles_are_deterministic_and_network_bound() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = parse_recovery_phrase(phrase).expect("valid phrase");
        let mut first = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        let mut second = create_descriptor_wallet(&mnemonic, Network::Regtest).expect("wallet");
        assert_eq!(
            next_receive_address(&mut first),
            next_receive_address(&mut second)
        );
    }

    #[test]
    fn new_wallet_birthday_does_not_start_at_genesis() {
        let state = KyotoWalletState::new_wallet(850_000, 1);
        assert_eq!(state.birthday_height, 850_000);
        assert_eq!(state.scanned_height, 850_000);
    }

    #[test]
    fn native_htlc_script_and_funding_are_exact() {
        let htlc = htlc();
        htlc.validate().expect("canonical script");
        let tx = funding(&htlc, 50_000);
        let verified =
            verify_htlc_funding(&serialize(&tx), &htlc, 50_000, 6, 6).expect("verified funding");
        assert_eq!(verified.output_index, 0);
        assert!(verify_htlc_funding(&serialize(&tx), &htlc, 50_001, 6, 6).is_err());
    }

    #[test]
    fn redeem_reveals_preimage_and_refund_enforces_height() {
        let htlc = htlc();
        let tx = funding(&htlc, 50_000);
        let lock =
            verify_htlc_funding(&serialize(&tx), &htlc, 50_000, 6, 6).expect("verified funding");
        let destination = ScriptBuf::new_p2wpkh(&key(8).wpubkey_hash().expect("compressed"));
        let preimage = [9_u8; 32];
        let redeem = prepare_htlc_spend(
            &lock,
            destination.clone(),
            500,
            HtlcSpendBranch::Redeem,
            Some(&preimage),
            400,
        )
        .expect("redeem template");
        assert_eq!(
            observe_preimage(&serialize(&redeem), &lock).expect("valid spend evidence"),
            Some(preimage)
        );
        assert!(matches!(
            prepare_htlc_spend(
                &lock,
                destination.clone(),
                500,
                HtlcSpendBranch::Refund,
                None,
                499
            ),
            Err(BitcoinWalletError::TimelockNotReached)
        ));
        let refund =
            prepare_htlc_spend(&lock, destination, 500, HtlcSpendBranch::Refund, None, 500)
                .expect("refund template");
        assert_eq!(
            refund.lock_time,
            absolute::LockTime::from_height(500).unwrap()
        );
    }

    #[test]
    fn reorg_rewinds_wallet_owned_progress() {
        let mut state = KyotoWalletState {
            birthday_height: 100,
            validated_height: 130,
            scanned_height: 128,
            last_consistent_height: 128,
            relevant_block_hashes: vec![[1; 32]; 29],
            last_started_at_unix: 1,
        };
        state.rewind_for_reorg(120);
        assert_eq!(state.validated_height, 120);
        assert_eq!(state.scanned_height, 120);
        assert_eq!(state.relevant_block_hashes.len(), 21);
    }
}
