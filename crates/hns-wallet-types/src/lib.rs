#![doc = "Wallet-local semantics which are not canonical chain or wire types."]
#![forbid(unsafe_code)]

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

macro_rules! semantic_id {
    ($name:ident, $size:expr) => {
        #[derive(
            Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name([u8; $size]);

        impl $name {
            pub const LENGTH: usize = $size;

            pub const fn new(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }
    };
}

semantic_id!(WalletId, 16);
semantic_id!(AccountId, 16);
semantic_id!(ApprovalId, 16);
semantic_id!(PermissionId, 16);
semantic_id!(WorkflowId, 16);
semantic_id!(SessionId, 32);
semantic_id!(ObjectHash, 32);
semantic_id!(TransactionHash, 32);

/// A wallet-local module selector. Canonical marketplace wire identifiers live
/// in `hns-rs`; this enum selects an installed wallet implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleId {
    Handshake,
    Bitcoin,
    Ethereum,
}

impl ModuleId {
    pub const fn asset(self) -> WalletAsset {
        match self {
            Self::Handshake => WalletAsset::Hns,
            Self::Bitcoin => WalletAsset::Btc,
            Self::Ethereum => WalletAsset::Eth,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WalletAsset {
    Hns,
    Btc,
    Eth,
}

/// Integer base units serialized as a decimal string so JavaScript cannot lose
/// precision.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BaseUnits(u128);

impl BaseUnits {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, AmountError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(AmountError::Underflow)
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Serialize for BaseUnits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for BaseUnits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        text.parse::<u128>()
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AmountError {
    #[error("amount overflow")]
    Overflow,
    #[error("amount underflow")]
    Underflow,
    #[error("amount asset mismatch")]
    AssetMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Amount {
    pub asset: WalletAsset,
    pub base_units: BaseUnits,
}

impl Amount {
    pub const fn new(asset: WalletAsset, base_units: u128) -> Self {
        Self {
            asset,
            base_units: BaseUnits::new(base_units),
        }
    }

    pub fn checked_add(self, other: Self) -> Result<Self, AmountError> {
        if self.asset != other.asset {
            return Err(AmountError::AssetMismatch);
        }
        Ok(Self {
            asset: self.asset,
            base_units: self.base_units.checked_add(other.base_units)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    Disabled,
    Starting,
    Headers,
    Filters,
    WalletScan,
    Ready,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncStatus {
    pub phase: SyncPhase,
    pub validated_height: u64,
    pub scanned_height: u64,
    pub target_height: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTransactionStatus {
    Prepared,
    Authorized,
    Broadcast,
    Mempool,
    Confirmed,
    Replaced,
    Conflicted,
    Reorged,
    Dropped,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub module: ModuleId,
    pub txid: TransactionHash,
    pub status: LocalTransactionStatus,
    pub net_amount: SignedBaseUnits,
    pub fee: Option<BaseUnits>,
    pub block_height: Option<u64>,
    pub first_seen_unix: Option<u64>,
    pub confirmation_count: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedBaseUnits {
    pub negative: bool,
    pub magnitude: BaseUnits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiveTarget {
    pub module: ModuleId,
    pub account: AccountId,
    pub display: String,
    pub derivation_index: u32,
}

impl ReceiveTarget {
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.display.is_empty() || self.display.len() > 512 {
            return Err(TypeError::InvalidLength {
                field: "receive target",
                maximum: 512,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivationReference {
    pub role: KeyRole,
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    HnsCoin,
    HnsName,
    HnsShakedex,
    HnsAtomicSwap,
    HnsIdentity,
    HnsDappSession,
    BitcoinWallet,
    BitcoinAtomicSwap,
    EthereumWallet,
    EthereumAtomicSwap,
    MetadataEncryption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainCapabilities {
    pub receive: bool,
    pub send: bool,
    pub history: bool,
    pub atomic_settlement: bool,
    pub hash_algorithm: HashAlgorithm,
    pub locktime_model: LocktimeModel,
    pub finality_model: FinalityModel,
    pub fee_model: FeeModel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    Sha256,
    Keccak256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocktimeModel {
    None,
    BlockHeight,
    UnixTime,
    SmartContractTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityModel {
    ProofOfWorkConfirmations,
    EthereumFinalizedCheckpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeModel {
    WeightRate,
    GasAndPriority,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCapability {
    Accounts,
    Balance,
    Transactions,
    ReceiveTarget,
    Send,
    Names,
    NameTransfer,
    NameFinalize,
    TypedIdentitySignature,
    NameMarket,
    CrossChainMarket,
    SwapSettlement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Permission,
    ModuleEnablement,
    Send,
    NameTransfer,
    NameFinalize,
    TypedSignature,
    NameMarketOffer,
    NameMarketPurchase,
    MarketIntent,
    FillAcceptance,
    SwapRedeem,
    SwapRefund,
    RecoveryPhraseDisplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    HnsSend,
    NameTransfer,
    NameFinalize,
    ShakedexSeller,
    ShakedexBuyer,
    MarketIntent,
    FillReservation,
    AtomicSwap,
    Refund,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedWorkflowReference {
    pub id: WorkflowId,
    pub kind: WorkflowKind,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TypeError {
    #[error("{field} is empty or exceeds {maximum} bytes")]
    InvalidLength { field: &'static str, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_units_are_json_strings_and_checked() {
        let maximum = BaseUnits::new(u128::MAX);
        assert_eq!(
            serde_json::to_string(&maximum).expect("serialize"),
            format!("\"{}\"", u128::MAX)
        );
        assert_eq!(
            serde_json::from_str::<BaseUnits>("\"42\"").expect("deserialize"),
            BaseUnits::new(42)
        );
        assert_eq!(
            maximum.checked_add(BaseUnits::new(1)),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn module_assets_cannot_be_confused() {
        assert_eq!(ModuleId::Handshake.asset(), WalletAsset::Hns);
        assert_eq!(ModuleId::Bitcoin.asset(), WalletAsset::Btc);
        assert_eq!(ModuleId::Ethereum.asset(), WalletAsset::Eth);
        assert_eq!(
            Amount::new(WalletAsset::Hns, 1).checked_add(Amount::new(WalletAsset::Btc, 1)),
            Err(AmountError::AssetMismatch)
        );
    }
}
