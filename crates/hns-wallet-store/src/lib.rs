#![doc = "Transactional wallet persistence with per-record authenticated encryption."]
#![forbid(unsafe_code)]

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hns_wallet_types::{ApprovalId, WorkflowId, WorkflowKind};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_RECORD_ID_BYTES: usize = 128;
pub const MAX_SECRET_BYTES: usize = 1_048_576;
pub const MAX_STATE_BYTES: usize = 1_048_576;
pub const MAX_REPLAY_ROWS_PER_ORIGIN: usize = 4_096;

const DATABASE_ID_BYTES: usize = 16;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const SENTINEL: &[u8] = b"hns-wallet-store-key-check-v1";
const AAD_DOMAIN: &[u8] = b"hns-wallet-store/record/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KdfConfig {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            lanes: 1,
        }
    }
}

impl KdfConfig {
    fn validate(self) -> Result<(), StoreError> {
        if self.memory_kib < 19_456 || self.iterations < 2 || self.lanes == 0 || self.lanes > 4 {
            return Err(StoreError::UnsafeKdfParameters);
        }
        Params::new(
            self.memory_kib,
            self.iterations,
            self.lanes,
            Some(KEY_BYTES),
        )
        .map_err(|_| StoreError::UnsafeKdfParameters)?;
        Ok(())
    }

    #[cfg(test)]
    const fn testing() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            lanes: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    RecoverySeed,
    PrivateKey,
    MetadataKey,
    HtlcPreimage,
    ProviderCapability,
    SessionAuthorization,
}

impl SecretKind {
    const fn label(self) -> &'static str {
        match self {
            Self::RecoverySeed => "recovery_seed",
            Self::PrivateKey => "private_key",
            Self::MetadataKey => "metadata_key",
            Self::HtlcPreimage => "htlc_preimage",
            Self::ProviderCapability => "provider_capability",
            Self::SessionAuthorization => "session_authorization",
        }
    }
}

pub struct WalletStore {
    connection: Connection,
    database_id: [u8; DATABASE_ID_BYTES],
    salt: [u8; SALT_BYTES],
    kdf: KdfConfig,
    key: Option<Zeroizing<[u8; KEY_BYTES]>>,
}

impl WalletStore {
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        Self::create_with_kdf(path, passphrase, KdfConfig::default())
    }

    fn create_with_kdf(
        path: impl AsRef<Path>,
        passphrase: &str,
        kdf: KdfConfig,
    ) -> Result<Self, StoreError> {
        kdf.validate()?;
        let connection = Connection::open(path)?;
        configure(&connection)?;
        migrate(&connection)?;
        if meta(&connection, "database_id")?.is_some() {
            return Err(StoreError::AlreadyInitialized);
        }

        let mut database_id = [0_u8; DATABASE_ID_BYTES];
        let mut salt = [0_u8; SALT_BYTES];
        getrandom::fill(&mut database_id).map_err(|_| StoreError::Randomness)?;
        getrandom::fill(&mut salt).map_err(|_| StoreError::Randomness)?;
        let key = derive_key(passphrase, &salt, kdf)?;
        let sentinel = encrypt_record(
            &key,
            &database_id,
            SecretKind::MetadataKey.label(),
            b"key_check",
            SENTINEL,
        )?;
        let kdf_json = serde_json::to_vec(&kdf)?;

        let transaction = connection.unchecked_transaction()?;
        set_meta(&transaction, "database_id", &database_id)?;
        set_meta(&transaction, "kdf_salt", &salt)?;
        set_meta(&transaction, "kdf_config", &kdf_json)?;
        set_meta(&transaction, "key_check", &sentinel)?;
        transaction.commit()?;

        Ok(Self {
            connection,
            database_id,
            salt,
            kdf,
            key: Some(key),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        configure(&connection)?;
        migrate(&connection)?;
        let database_id =
            exact_array::<DATABASE_ID_BYTES>(required_meta(&connection, "database_id")?)?;
        let salt = exact_array::<SALT_BYTES>(required_meta(&connection, "kdf_salt")?)?;
        let kdf: KdfConfig = serde_json::from_slice(&required_meta(&connection, "kdf_config")?)?;
        kdf.validate()?;
        Ok(Self {
            connection,
            database_id,
            salt,
            kdf,
            key: None,
        })
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), StoreError> {
        let key = derive_key(passphrase, &self.salt, self.kdf)?;
        let encrypted = required_meta(&self.connection, "key_check")?;
        let clear = decrypt_record(
            &key,
            &self.database_id,
            SecretKind::MetadataKey.label(),
            b"key_check",
            &encrypted,
        )
        .map_err(|_| StoreError::InvalidPassphrase)?;
        if clear.as_slice() != SENTINEL {
            return Err(StoreError::InvalidPassphrase);
        }
        self.key = Some(key);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.key = None;
    }

    pub const fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    pub const fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    pub fn put_secret(
        &mut self,
        id: &[u8],
        kind: SecretKind,
        cleartext: &[u8],
        updated_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_id(id)?;
        if cleartext.is_empty() || cleartext.len() > MAX_SECRET_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let encrypted = encrypt_record(key, &self.database_id, kind.label(), id, cleartext)?;
        self.connection.execute(
            "INSERT INTO secrets(id, kind, encrypted_value, updated_at_unix) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, encrypted_value=excluded.encrypted_value,
             updated_at_unix=excluded.updated_at_unix",
            params![id, kind.label(), encrypted, updated_at_unix],
        )?;
        Ok(())
    }

    pub fn get_secret(
        &self,
        id: &[u8],
        expected_kind: SecretKind,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        validate_id(id)?;
        let key = self.key.as_ref().ok_or(StoreError::Locked)?;
        let row: Option<(String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT kind, encrypted_value FROM secrets WHERE id=?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((kind, encrypted)) = row else {
            return Ok(None);
        };
        if kind != expected_kind.label() {
            return Err(StoreError::KindMismatch);
        }
        decrypt_record(
            key,
            &self.database_id,
            expected_kind.label(),
            id,
            &encrypted,
        )
        .map(Some)
    }

    pub fn delete_secret(&mut self, id: &[u8]) -> Result<bool, StoreError> {
        validate_id(id)?;
        self.key.as_ref().ok_or(StoreError::Locked)?;
        Ok(self
            .connection
            .execute("DELETE FROM secrets WHERE id=?1", params![id])?
            == 1)
    }

    /// Compare-and-swap a persisted workflow revision. A caller must complete
    /// this operation before broadcasting the transaction represented by
    /// `state`.
    pub fn save_workflow<T: Serialize>(
        &mut self,
        id: WorkflowId,
        kind: WorkflowKind,
        expected_revision: u64,
        state: &T,
        irreversible_broadcast_prepared: bool,
        updated_at_unix: u64,
    ) -> Result<u64, StoreError> {
        let encoded = serde_json::to_vec(state)?;
        if encoded.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<u64> = transaction
            .query_row(
                "SELECT revision FROM workflows WHERE id=?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let actual = current.unwrap_or(0);
        if actual != expected_revision {
            return Err(StoreError::StaleRevision {
                expected: expected_revision,
                actual,
            });
        }
        let next = actual.checked_add(1).ok_or(StoreError::RevisionOverflow)?;
        transaction.execute(
            "INSERT INTO workflows(id, kind, revision, state_json, broadcast_prepared, updated_at_unix)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, revision=excluded.revision,
             state_json=excluded.state_json, broadcast_prepared=excluded.broadcast_prepared,
             updated_at_unix=excluded.updated_at_unix",
            params![
                id.as_bytes().as_slice(),
                workflow_kind(kind),
                next,
                encoded,
                irreversible_broadcast_prepared,
                updated_at_unix,
            ],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    pub fn load_workflow<T: for<'de> Deserialize<'de>>(
        &self,
        id: WorkflowId,
    ) -> Result<Option<StoredWorkflow<T>>, StoreError> {
        let row: Option<(String, u64, Vec<u8>, bool, u64)> = self
            .connection
            .query_row(
                "SELECT kind, revision, state_json, broadcast_prepared, updated_at_unix
                 FROM workflows WHERE id=?1",
                params![id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(kind, revision, state, broadcast_prepared, updated_at_unix)| {
                Ok(StoredWorkflow {
                    id,
                    kind: parse_workflow_kind(&kind)?,
                    revision,
                    state: serde_json::from_slice(&state)?,
                    irreversible_broadcast_prepared: broadcast_prepared,
                    updated_at_unix,
                })
            },
        )
        .transpose()
    }

    pub fn put_provider_permission(
        &mut self,
        origin: &str,
        generation: u64,
        permission_json: &[u8],
        updated_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if permission_json.is_empty() || permission_json.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        self.connection.execute(
            "INSERT INTO provider_permissions(origin, generation, permission_json, updated_at_unix)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(origin) DO UPDATE SET generation=excluded.generation,
             permission_json=excluded.permission_json, updated_at_unix=excluded.updated_at_unix",
            params![origin, generation, permission_json, updated_at_unix],
        )?;
        Ok(())
    }

    pub fn provider_permission(&self, origin: &str) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        validate_origin(origin)?;
        self.connection
            .query_row(
                "SELECT generation, permission_json FROM provider_permissions WHERE origin=?1",
                params![origin],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn revoke_provider_permission(&mut self, origin: &str) -> Result<bool, StoreError> {
        validate_origin(origin)?;
        Ok(self.connection.execute(
            "DELETE FROM provider_permissions WHERE origin=?1",
            params![origin],
        )? == 1)
    }

    pub fn put_pending_approval(
        &mut self,
        id: ApprovalId,
        origin: &str,
        request_json: &[u8],
        expires_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if request_json.is_empty() || request_json.len() > MAX_STATE_BYTES {
            return Err(StoreError::RecordTooLarge);
        }
        self.connection.execute(
            "INSERT INTO pending_approvals(id, origin, request_json, expires_at_unix)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                id.as_bytes().as_slice(),
                origin,
                request_json,
                expires_at_unix
            ],
        )?;
        Ok(())
    }

    /// Atomically consumes a request nonce. Duplicate live nonces fail.
    pub fn consume_replay_nonce(
        &mut self,
        origin: &str,
        nonce: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<(), StoreError> {
        validate_origin(origin)?;
        if nonce == 0 || expires_at_unix <= now_unix {
            return Err(StoreError::InvalidReplayWindow);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM replay_protection WHERE expires_at_unix <= ?1",
            params![now_unix],
        )?;
        let count: usize = transaction.query_row(
            "SELECT COUNT(*) FROM replay_protection WHERE origin=?1",
            params![origin],
            |row| row.get(0),
        )?;
        if count >= MAX_REPLAY_ROWS_PER_ORIGIN {
            return Err(StoreError::ReplayCapacity);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO replay_protection(origin, nonce, expires_at_unix)
             VALUES(?1, ?2, ?3)",
            params![origin, nonce, expires_at_unix],
        )?;
        if inserted != 1 {
            return Err(StoreError::Replay);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn connection_for_module_transaction(&mut self) -> Result<&mut Connection, StoreError> {
        self.key.as_ref().ok_or(StoreError::Locked)?;
        Ok(&mut self.connection)
    }

    #[cfg(test)]
    fn create_in_memory(passphrase: &str) -> Result<Self, StoreError> {
        Self::create_with_kdf(":memory:", passphrase, KdfConfig::testing())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredWorkflow<T> {
    pub id: WorkflowId,
    pub kind: WorkflowKind,
    pub revision: u64,
    pub state: T,
    pub irreversible_broadcast_prepared: bool,
    pub updated_at_unix: u64,
}

fn configure(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA secure_delete=ON;
         PRAGMA synchronous=FULL;
         PRAGMA journal_mode=WAL;",
    )?;
    Ok(())
}

fn migrate(connection: &Connection) -> Result<(), StoreError> {
    let current: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema(current));
    }
    if current == 0 {
        connection.execute_batch(SCHEMA_V1)?;
    }
    Ok(())
}

const SCHEMA_V1: &str = r#"
BEGIN IMMEDIATE;
CREATE TABLE wallet_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE secrets(
    id BLOB PRIMARY KEY, kind TEXT NOT NULL, encrypted_value BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL
) STRICT;
CREATE TABLE wallet_accounts(id BLOB PRIMARY KEY, module TEXT NOT NULL, state_json BLOB NOT NULL) STRICT;
CREATE TABLE derived_addresses(account_id BLOB NOT NULL, derivation_index INTEGER NOT NULL,
    address TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(account_id, derivation_index)) STRICT;
CREATE TABLE hns_utxos(outpoint BLOB PRIMARY KEY, account_id BLOB NOT NULL, value INTEGER NOT NULL,
    script BLOB NOT NULL, height INTEGER, spent_by BLOB) STRICT;
CREATE TABLE hns_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE known_names(name_hash BLOB PRIMARY KEY, name TEXT NOT NULL, state_json BLOB NOT NULL,
    checked_height INTEGER NOT NULL) STRICT;
CREATE TABLE name_owner_outpoints(name_hash BLOB PRIMARY KEY, outpoint BLOB NOT NULL,
    proof_root BLOB NOT NULL, checked_height INTEGER NOT NULL) STRICT;
CREATE TABLE name_transfer_state(name_hash BLOB PRIMARY KEY, workflow_id BLOB NOT NULL,
    state_json BLOB NOT NULL) STRICT;
CREATE TABLE shakedex_state(id BLOB PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE denuo_board_cache(object_hash BLOB PRIMARY KEY, protocol INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_headers(height INTEGER PRIMARY KEY, block_hash BLOB NOT NULL,
    header BLOB NOT NULL, chainwork BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_filter_headers(height INTEGER PRIMARY KEY, block_hash BLOB NOT NULL,
    filter_header BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_peers(peer_id TEXT PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE bitcoin_scan_state(account_id BLOB PRIMARY KEY, birthday_height INTEGER,
    scanned_height INTEGER NOT NULL, checkpoint_json BLOB NOT NULL) STRICT;
CREATE TABLE bitcoin_utxos(outpoint BLOB PRIMARY KEY, account_id BLOB NOT NULL,
    value INTEGER NOT NULL, script BLOB NOT NULL, height INTEGER, spent_by BLOB) STRICT;
CREATE TABLE bitcoin_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE ethereum_accounts(id BLOB PRIMARY KEY, address BLOB NOT NULL,
    state_json BLOB NOT NULL) STRICT;
CREATE TABLE ethereum_transactions(txid BLOB PRIMARY KEY, raw BLOB, status_json BLOB NOT NULL,
    first_seen_unix INTEGER NOT NULL) STRICT;
CREATE TABLE market_intents(id BLOB PRIMARY KEY, sequence INTEGER NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE fill_grants(id BLOB PRIMARY KEY, intent_id BLOB NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE price_rounds(round_hash BLOB PRIMARY KEY, pair TEXT NOT NULL,
    state_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE swap_sessions(id BLOB PRIMARY KEY, state_json BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE htlc_secrets(session_id BLOB PRIMARY KEY, encrypted_secret BLOB NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE refund_transactions(session_id BLOB NOT NULL, module TEXT NOT NULL,
    txid BLOB, state_json BLOB NOT NULL, PRIMARY KEY(session_id, module)) STRICT;
CREATE TABLE provider_permissions(origin TEXT PRIMARY KEY, generation INTEGER NOT NULL,
    permission_json BLOB NOT NULL, updated_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE pending_approvals(id BLOB PRIMARY KEY, origin TEXT NOT NULL,
    request_json BLOB NOT NULL, expires_at_unix INTEGER NOT NULL) STRICT;
CREATE TABLE replay_protection(origin TEXT NOT NULL, nonce INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL, PRIMARY KEY(origin, nonce)) STRICT;
CREATE INDEX replay_expiry ON replay_protection(expires_at_unix);
CREATE TABLE workflows(id BLOB PRIMARY KEY, kind TEXT NOT NULL, revision INTEGER NOT NULL,
    state_json BLOB NOT NULL, broadcast_prepared INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL) STRICT;
PRAGMA user_version=1;
COMMIT;
"#;

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_BYTES],
    config: KdfConfig,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, StoreError> {
    config.validate()?;
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.lanes,
        Some(KEY_BYTES),
    )
    .map_err(|_| StoreError::UnsafeKdfParameters)?;
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| StoreError::KeyDerivation)?;
    Ok(key)
}

fn encrypt_record(
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
    cleartext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| StoreError::Randomness)?;
    let aad = record_aad(database_id, kind, id)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: cleartext,
                aad: &aad,
            },
        )
        .map_err(|_| StoreError::Encryption)?;
    let mut envelope = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    nonce.zeroize();
    Ok(envelope)
}

fn decrypt_record(
    key: &[u8; KEY_BYTES],
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if envelope.len() <= NONCE_BYTES || envelope.len() > MAX_SECRET_BYTES + NONCE_BYTES + 16 {
        return Err(StoreError::Encryption);
    }
    let (nonce, ciphertext) = envelope.split_at(NONCE_BYTES);
    let aad = record_aad(database_id, kind, id)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Encryption)
}

fn record_aad(
    database_id: &[u8; DATABASE_ID_BYTES],
    kind: &str,
    id: &[u8],
) -> Result<Vec<u8>, StoreError> {
    validate_id(id)?;
    if kind.is_empty() || kind.len() > 64 {
        return Err(StoreError::InvalidRecordId);
    }
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + database_id.len() + kind.len() + id.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(database_id);
    aad.extend_from_slice(kind.as_bytes());
    aad.push(0);
    aad.extend_from_slice(id);
    Ok(aad)
}

fn validate_id(id: &[u8]) -> Result<(), StoreError> {
    if id.is_empty() || id.len() > MAX_RECORD_ID_BYTES {
        return Err(StoreError::InvalidRecordId);
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), StoreError> {
    if origin.is_empty() || origin.len() > 512 || !origin.is_ascii() {
        return Err(StoreError::InvalidOrigin);
    }
    Ok(())
}

fn meta(connection: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    connection
        .query_row(
            "SELECT value FROM wallet_meta WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
}

fn required_meta(connection: &Connection, key: &str) -> Result<Vec<u8>, StoreError> {
    meta(connection, key)?.ok_or(StoreError::NotInitialized)
}

fn set_meta(
    transaction: &rusqlite::Transaction<'_>,
    key: &str,
    value: &[u8],
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO wallet_meta(key, value) VALUES(?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn exact_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptMetadata)
}

const fn workflow_kind(kind: WorkflowKind) -> &'static str {
    match kind {
        WorkflowKind::HnsSend => "hns_send",
        WorkflowKind::NameTransfer => "name_transfer",
        WorkflowKind::NameFinalize => "name_finalize",
        WorkflowKind::ShakedexSeller => "shakedex_seller",
        WorkflowKind::ShakedexBuyer => "shakedex_buyer",
        WorkflowKind::MarketIntent => "market_intent",
        WorkflowKind::FillReservation => "fill_reservation",
        WorkflowKind::AtomicSwap => "atomic_swap",
        WorkflowKind::Refund => "refund",
    }
}

fn parse_workflow_kind(value: &str) -> Result<WorkflowKind, StoreError> {
    match value {
        "hns_send" => Ok(WorkflowKind::HnsSend),
        "name_transfer" => Ok(WorkflowKind::NameTransfer),
        "name_finalize" => Ok(WorkflowKind::NameFinalize),
        "shakedex_seller" => Ok(WorkflowKind::ShakedexSeller),
        "shakedex_buyer" => Ok(WorkflowKind::ShakedexBuyer),
        "market_intent" => Ok(WorkflowKind::MarketIntent),
        "fill_reservation" => Ok(WorkflowKind::FillReservation),
        "atomic_swap" => Ok(WorkflowKind::AtomicSwap),
        "refund" => Ok(WorkflowKind::Refund),
        _ => Err(StoreError::CorruptMetadata),
    }
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("wallet store is already initialized")]
    AlreadyInitialized,
    #[error("wallet store is not initialized")]
    NotInitialized,
    #[error("wallet store is locked")]
    Locked,
    #[error("invalid wallet passphrase")]
    InvalidPassphrase,
    #[error("unsafe or unsupported Argon2 parameters")]
    UnsafeKdfParameters,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("authenticated encryption failed")]
    Encryption,
    #[error("secret kind does not match the requested kind")]
    KindMismatch,
    #[error("record identifier is invalid")]
    InvalidRecordId,
    #[error("origin is invalid")]
    InvalidOrigin,
    #[error("record exceeds its bounded maximum")]
    RecordTooLarge,
    #[error("wallet metadata is corrupt")]
    CorruptMetadata,
    #[error("database schema {0} is newer than this wallet")]
    NewerSchema(u32),
    #[error("stale workflow revision: expected {expected}, actual {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("workflow revision overflow")]
    RevisionOverflow,
    #[error("request nonce has already been consumed")]
    Replay,
    #[error("request replay window is invalid")]
    InvalidReplayWindow,
    #[error("origin replay-protection capacity is exhausted")]
    ReplayCapacity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secrets_require_unlock_and_ciphertext_does_not_contain_cleartext() {
        let mut store = WalletStore::create_in_memory("correct horse battery staple")
            .expect("create encrypted store");
        store
            .put_secret(
                b"seed",
                SecretKind::RecoverySeed,
                b"never persist me clear",
                1,
            )
            .expect("put secret");
        let raw: Vec<u8> = store
            .connection
            .query_row(
                "SELECT encrypted_value FROM secrets WHERE id=?1",
                params![b"seed".as_slice()],
                |row| row.get(0),
            )
            .expect("raw envelope");
        assert!(
            !raw.windows(b"never persist me clear".len())
                .any(|window| window == b"never persist me clear")
        );
        assert_eq!(
            store
                .get_secret(b"seed", SecretKind::RecoverySeed)
                .expect("decrypt")
                .expect("present")
                .as_slice(),
            b"never persist me clear"
        );
        store.lock();
        assert!(matches!(
            store.get_secret(b"seed", SecretKind::RecoverySeed),
            Err(StoreError::Locked)
        ));
    }

    #[test]
    fn workflow_updates_are_compare_and_swap_and_persist_before_broadcast() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        let id = WorkflowId::new([7; 16]);
        let revision = store
            .save_workflow(
                id,
                WorkflowKind::AtomicSwap,
                0,
                &json!({"state":"terms_frozen"}),
                true,
                5,
            )
            .expect("first revision");
        assert_eq!(revision, 1);
        assert!(matches!(
            store.save_workflow(id, WorkflowKind::AtomicSwap, 0, &json!({}), true, 6),
            Err(StoreError::StaleRevision { .. })
        ));
        let loaded: StoredWorkflow<serde_json::Value> =
            store.load_workflow(id).expect("load").expect("present");
        assert!(loaded.irreversible_broadcast_prepared);
        assert_eq!(loaded.revision, 1);
    }

    #[test]
    fn replay_nonces_are_atomic_and_expiring() {
        let mut store = WalletStore::create_in_memory("passphrase").expect("store");
        store
            .consume_replay_nonce("https://example", 1, 10, 20)
            .expect("first use");
        assert!(matches!(
            store.consume_replay_nonce("https://example", 1, 11, 20),
            Err(StoreError::Replay)
        ));
        store
            .consume_replay_nonce("https://example", 1, 20, 30)
            .expect("expired nonce can be reused in a new bounded session");
    }
}
