use std::collections::BTreeSet;

use hns_swap::{FixedPriceListing, ListingCancellation};
use hns_wallet_store::WalletStore;
use hns_wallet_types::ObjectHash;
use serde::{Deserialize, Serialize};

use crate::{
    MAX_NAME_MARKET_BOARD_OFFERS, ShakedexError, VerifiedFixedPriceListing,
    VerifiedListingCancellation,
};

const NAME_MARKET_BOARD_SCHEMA_VERSION: u16 = 1;
pub const NAME_MARKET_BOARD_RECORD_ID: &[u8] = b"canonical-name-market-board-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardOfferStatus {
    Active,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersistedBoardOffer {
    pub listing_hash: ObjectHash,
    pub listing_bytes: Vec<u8>,
    pub network_magic: u32,
    pub network_genesis: ObjectHash,
    pub name_hash: ObjectHash,
    pub seller_public_key: Vec<u8>,
    pub sequence: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: BoardOfferStatus,
    pub cancellation_hash: Option<ObjectHash>,
    pub cancellation_bytes: Option<Vec<u8>>,
    pub cancellation_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SequenceWatermark {
    network_magic: u32,
    network_genesis: ObjectHash,
    name_hash: ObjectHash,
    seller_public_key: Vec<u8>,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameMarketBoard {
    schema_version: u16,
    offers: Vec<PersistedBoardOffer>,
    watermarks: Vec<SequenceWatermark>,
}

impl Default for NameMarketBoard {
    fn default() -> Self {
        Self {
            schema_version: NAME_MARKET_BOARD_SCHEMA_VERSION,
            offers: Vec::new(),
            watermarks: Vec::new(),
        }
    }
}

impl NameMarketBoard {
    pub fn offers(&self) -> &[PersistedBoardOffer] {
        &self.offers
    }

    pub fn offer(&self, hash: ObjectHash) -> Option<&PersistedBoardOffer> {
        self.offers.iter().find(|offer| offer.listing_hash == hash)
    }

    pub fn apply_offer(
        &mut self,
        listing: &VerifiedFixedPriceListing,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let name_hash = listing.name_hash()?;
        let network = listing.network();
        let seller_public_key = listing.seller_public_key().to_vec();
        if let Some(existing) = self.offer(listing.listing_hash()) {
            if existing.listing_bytes == listing.encoded()
                && existing.sequence == listing.sequence()
            {
                return Ok(false);
            }
            return Err(ShakedexError::NameMarketReplay);
        }

        let offer_index = self.offers.iter().position(|offer| {
            offer.network_magic == network.magic
                && offer.network_genesis.into_bytes() == *network.genesis.as_bytes()
                && offer.name_hash == name_hash
                && offer.seller_public_key == seller_public_key
        });
        if offer_index.is_none() && self.offers.len() >= MAX_NAME_MARKET_BOARD_OFFERS {
            return Err(ShakedexError::NameMarketBoardCapacity);
        }

        let watermark = self.watermarks.iter_mut().find(|watermark| {
            watermark.network_magic == network.magic
                && watermark.network_genesis.into_bytes() == *network.genesis.as_bytes()
                && watermark.name_hash == name_hash
                && watermark.seller_public_key == seller_public_key
        });
        match watermark {
            Some(watermark) if listing.sequence() <= watermark.sequence => {
                return Err(ShakedexError::NameMarketReplay);
            }
            Some(watermark) => watermark.sequence = listing.sequence(),
            None => {
                if self.watermarks.len() >= MAX_NAME_MARKET_BOARD_OFFERS {
                    return Err(ShakedexError::NameMarketBoardCapacity);
                }
                self.watermarks.push(SequenceWatermark {
                    network_magic: network.magic,
                    network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
                    name_hash,
                    seller_public_key: seller_public_key.clone(),
                    sequence: listing.sequence(),
                });
            }
        }

        let replacement = PersistedBoardOffer {
            listing_hash: listing.listing_hash(),
            listing_bytes: listing.encoded().to_vec(),
            network_magic: network.magic,
            network_genesis: ObjectHash::new(*network.genesis.as_bytes()),
            name_hash,
            seller_public_key,
            sequence: listing.sequence(),
            created_at_unix: listing.created_at_unix(),
            expires_at_unix: listing.expires_at_unix(),
            status: BoardOfferStatus::Active,
            cancellation_hash: None,
            cancellation_bytes: None,
            cancellation_sequence: None,
        };
        if let Some(index) = offer_index {
            self.offers[index] = replacement;
        } else {
            self.offers.push(replacement);
        }
        self.offers.sort_by_key(|offer| offer.listing_hash);
        self.watermarks
            .sort_by(|left, right| watermark_key(left).cmp(&watermark_key(right)));
        Ok(true)
    }

    pub fn apply_cancellation(
        &mut self,
        cancellation: &VerifiedListingCancellation,
    ) -> Result<bool, ShakedexError> {
        self.validate()?;
        let offer_index = self
            .offers
            .iter()
            .position(|offer| offer.listing_hash == cancellation.listing_hash())
            .ok_or(ShakedexError::InvalidCancellation)?;
        let identity = {
            let offer = &self.offers[offer_index];
            (
                offer.network_magic,
                offer.network_genesis,
                offer.name_hash,
                offer.seller_public_key.clone(),
            )
        };
        let watermark = self
            .watermarks
            .iter_mut()
            .find(|watermark| {
                watermark.network_magic == identity.0
                    && watermark.network_genesis == identity.1
                    && watermark.name_hash == identity.2
                    && watermark.seller_public_key == identity.3
            })
            .ok_or(ShakedexError::CorruptNameMarketBoard)?;
        let offer = &mut self.offers[offer_index];
        if offer.cancellation_hash == Some(cancellation.cancellation_hash())
            && offer.cancellation_bytes.as_deref() == Some(cancellation.encoded())
        {
            return Ok(false);
        }
        if cancellation.sequence() <= watermark.sequence {
            return Err(ShakedexError::NameMarketReplay);
        }
        watermark.sequence = cancellation.sequence();
        offer.status = BoardOfferStatus::Cancelled;
        offer.cancellation_hash = Some(cancellation.cancellation_hash());
        offer.cancellation_bytes = Some(cancellation.encoded().to_vec());
        offer.cancellation_sequence = Some(cancellation.sequence());
        Ok(true)
    }

    pub fn active_inventory(&self, now_unix: u64) -> Result<Vec<ObjectHash>, ShakedexError> {
        self.validate()?;
        Ok(self
            .offers
            .iter()
            .filter(|offer| {
                offer.status == BoardOfferStatus::Active
                    && offer.created_at_unix <= now_unix
                    && now_unix < offer.expires_at_unix
            })
            .map(|offer| offer.listing_hash)
            .collect())
    }

    pub fn validate(&self) -> Result<(), ShakedexError> {
        if self.schema_version != NAME_MARKET_BOARD_SCHEMA_VERSION
            || self.offers.len() > MAX_NAME_MARKET_BOARD_OFFERS
            || self.watermarks.len() > MAX_NAME_MARKET_BOARD_OFFERS
            || self.offers.len() != self.watermarks.len()
            || self
                .offers
                .windows(2)
                .any(|window| window[0].listing_hash >= window[1].listing_hash)
            || self
                .watermarks
                .windows(2)
                .any(|window| watermark_key(&window[0]) >= watermark_key(&window[1]))
        {
            return Err(ShakedexError::CorruptNameMarketBoard);
        }
        let mut identities = BTreeSet::new();
        for offer in &self.offers {
            validate_offer(offer)?;
            if !identities.insert((
                offer.network_magic,
                offer.network_genesis,
                offer.name_hash,
                offer.seller_public_key.clone(),
            )) {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
            let watermark = self.watermarks.iter().find(|watermark| {
                watermark.network_magic == offer.network_magic
                    && watermark.network_genesis == offer.network_genesis
                    && watermark.name_hash == offer.name_hash
                    && watermark.seller_public_key == offer.seller_public_key
            });
            let minimum = offer.cancellation_sequence.unwrap_or(offer.sequence);
            if watermark.is_none_or(|watermark| watermark.sequence != minimum) {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
        }
        Ok(())
    }
}

fn validate_offer(offer: &PersistedBoardOffer) -> Result<(), ShakedexError> {
    let listing = FixedPriceListing::decode(&offer.listing_bytes)
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    let listing_hash = listing
        .listing_hash()
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    let name_hash = listing
        .name_hash()
        .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
    if listing_hash != offer.listing_hash.into_bytes()
        || listing.network().magic != offer.network_magic
        || listing.network().genesis.as_bytes() != &offer.network_genesis.into_bytes()
        || name_hash.as_bytes() != offer.name_hash.as_bytes()
        || listing.seller_public_key().as_slice() != offer.seller_public_key
        || listing.sequence != offer.sequence
        || listing.created_at != offer.created_at_unix
        || listing.expires_at != offer.expires_at_unix
    {
        return Err(ShakedexError::CorruptNameMarketBoard);
    }
    match (
        offer.status,
        offer.cancellation_hash,
        offer.cancellation_bytes.as_deref(),
        offer.cancellation_sequence,
    ) {
        (BoardOfferStatus::Cancelled, Some(hash), Some(bytes), Some(sequence)) => {
            let cancellation = ListingCancellation::decode(bytes)
                .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
            cancellation
                .verify_for_listing(&listing, listing.network(), cancellation.created_at)
                .map_err(|_| ShakedexError::CorruptNameMarketBoard)?;
            if cancellation
                .cancellation_hash()
                .map_err(|_| ShakedexError::CorruptNameMarketBoard)?
                != hash.into_bytes()
                || cancellation.sequence != sequence
            {
                return Err(ShakedexError::CorruptNameMarketBoard);
            }
        }
        (BoardOfferStatus::Active, None, None, None) => {}
        _ => return Err(ShakedexError::CorruptNameMarketBoard),
    }
    Ok(())
}

fn watermark_key(watermark: &SequenceWatermark) -> (u32, [u8; 32], [u8; 32], &[u8]) {
    (
        watermark.network_magic,
        watermark.network_genesis.into_bytes(),
        watermark.name_hash.into_bytes(),
        &watermark.seller_public_key,
    )
}

pub struct StoredNameMarketBoard {
    pub revision: u64,
    pub board: NameMarketBoard,
}

pub fn load_name_market_board(store: &WalletStore) -> Result<StoredNameMarketBoard, ShakedexError> {
    let stored = store.denuo_board_object(NAME_MARKET_BOARD_RECORD_ID)?;
    match stored {
        Some(stored) => {
            let board: NameMarketBoard = stored.value;
            board.validate()?;
            Ok(StoredNameMarketBoard {
                revision: stored.revision,
                board,
            })
        }
        None => Ok(StoredNameMarketBoard {
            revision: 0,
            board: NameMarketBoard::default(),
        }),
    }
}

pub fn save_name_market_board(
    store: &mut WalletStore,
    expected_revision: u64,
    board: &NameMarketBoard,
    updated_at_unix: u64,
) -> Result<u64, ShakedexError> {
    board.validate()?;
    store
        .save_denuo_board_object(
            NAME_MARKET_BOARD_RECORD_ID,
            expected_revision,
            board,
            updated_at_unix,
        )
        .map_err(ShakedexError::from)
}
