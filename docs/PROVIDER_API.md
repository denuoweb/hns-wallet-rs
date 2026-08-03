# Handshake Provider API

The website surface is `HandshakeProvider`, not `window.ethereum`:

```ts
interface HandshakeProvider {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeListener(event: string, listener: (...args: unknown[]) => void): void;
}
```

Discovery uses `hns:requestProvider` and `hns:announceProvider`. A convenience
global may be announced, but consumers must not depend on one mutable global.

## Methods

General:

`wallet_getCapabilities`, `wallet_getEnabledModules`, `wallet_enableModule`,
`wallet_disableModule`, `wallet_requestPermissions`, `wallet_getPermissions`,
`wallet_revokePermissions`, `wallet_lock`, `wallet_getStatus`.

Handshake:

`hns_requestAccounts`, `hns_accounts`, `hns_getBalance`,
`hns_getTransactions`, `hns_getReceiveAddress`, `hns_send`, `hns_getNames`,
`hns_getName`, `hns_importKnownName`, `hns_transferName`, `hns_finalizeName`,
`hns_signTypedMessage`.

The method vocabulary is stable even when a capability is unavailable. The HNS
runtime now persists split proof/current canonical summaries, exact current
resource bytes, and account-bound ownership/transfer direction after fresh
reconciliation; legacy rows stay explicitly watch-only. Provider dispatch for
these methods is not yet product-integrated. `hns_transferName` and
`hns_finalizeName` remain unavailable even though typed wallet-owned P2PKH
TRANSFER/direct-FINALIZE workflows now exist in the wallet source. Provider
dispatch, trusted product approval UI, adapter qualification, and both HNS
value gates are incomplete. Persisted status, incoming-recipient
classification, or a node projection never authorize signing.

External assets:

`asset_getAccount`, `asset_getBalance`, `asset_getTransactions`,
`asset_getReceiveTarget`, `asset_send`. Every call includes exactly one enabled
`bitcoin` or `ethereum` module. These methods never accept calldata or PSBTs.
Ethereum currently exposes offline receive derivation only; provider dispatch,
balance/history, send, signing, and settlement remain unavailable.

Name market:

`nameMarket_listOffers`, `nameMarket_createFixedPriceOffer`,
`nameMarket_cancelOffer`, `nameMarket_acceptOffer`, `nameMarket_getSession`,
`nameMarket_finalizePurchase`, `nameMarket_recoverName`.

Cross-chain market:

`swap_getSupportedPairs`, `swap_getPriceRound`, `swap_listMarketIntents`,
`swap_publishMarketIntent`, `swap_cancelMarketIntent`, `swap_requestMatch`,
`swap_acceptFill`, `swap_getSession`, `swap_redeem`, `swap_refund`.

## Events

`connect`, `disconnect`, `permissionsChanged`, `modulesChanged`,
`accountsChanged`, `balancesChanged`, `transactionsChanged`, `namesChanged`,
`nameMarketChanged`, `priceRoundChanged`, `marketIntentChanged`,
`swapSessionChanged`, `walletLocked`.

Events are private service frames scoped by an opaque host-issued authority
handle and exact service-owned revision. A navigation/policy/runtime change,
permission revocation or expiry, wallet-session rotation, authority
replacement/revoke, or service restart invalidates pending approvals and event
channels. Only the explicit disconnect event may be emitted after permission is
no longer active.

The browser host retains the engine-issued authority. Only its private control
channel may register the logical origin, namespace, runtime session/generation,
policy/navigation generations, decision fingerprint, and expiry. Pages never
supply those values as authentication and never receive the opaque handle.
Wallet lock/session and permission generation are owned by the wallet service.
The reusable host state machine mints the opaque handle and per-request nonce,
tracks the exact authority revision and current private binding, and correlates
each bounded request with only its allowed response class. Approval decisions
reuse host-retained ownership and expiry, and service events share one exact
incoming channel sequence with responses. None of that private state is a
website request field. Mandatory-approval methods cannot complete on their
initial request, approval IDs cannot be reused within a host session, and
permission or wallet-lock transitions must advance the exact generation or
session dimension before a result is accepted.

Permission records and encrypted tombstone generations survive service
restart. Their persistence scope is the exact selected namespace plus logical
origin, stored under a domain-separated opaque key; the record retains both
values and must match them when loaded. The service reads the current generation
from `WalletStore`; it never accepts one from a request. The first grant is
generation one and every later grant/revocation is exactly the stored generation
plus one. An Accounts grant also retains a bounded exact set of approved
wallet-local account IDs. A legacy or generic grant that claims Accounts
without that set fails closed. Every approved permission change carries the
generation authenticated by its prompt into the persisted compare-and-swap;
if another grant or revocation wins first, the old approval is stale and cannot
authorize the next generation. Every other approved call rechecks the active,
unexpired permission and generation immediately before execution. Provider
approvals, handle-bound replay state, rate windows, request-ID windows, and
event cursors are deliberately process-ephemeral. Their maximum approval
lifetime is 90 seconds, and old service sessions cannot resume them.
Time-bearing provider entry points also reject a process-local wall-clock
rollback instead of extending authority.

`wallet_lock` is service-owned: the runtime locks first, then the service rotates
the wallet session and clears approvals and event cursors. If fresh session
entropy is unavailable, the provider remains locked. Send prompts are accepted
only when the method, requested module, displayed chain, amount asset, and fee
asset agree exactly.

The 43 method names remain the closed vocabulary, but presence in that
vocabulary is not availability. Wallet types own the single canonical wire-name
list used by both provider parsing and private ABI snapshot validation; even a
short, bounded unknown name is rejected. The website method `wallet_getCapabilities`
returns only `{providerApiVersion:1,methods:[...]}`. Native bootstrap separately
uses the authority-scoped private ABI capability request whose snapshot is
`{providerSchemaVersion:1,approvalSchemaVersion:2,walletSessionId,
permissionGeneration,methods}`. The native adapter retains its result binding;
it must never project that private envelope to website code. Chromium must
project exactly `{abiVersion,available,walletSession,permissionGeneration,
methods}` from private negotiation. With provider dispatch unavailable, the
private method set is empty and `available` remains false.

Generation zero is valid only before the first grant or revocation;
`wallet_getPermissions` preserves a nonzero tombstone generation with an empty
capability list. An unimplemented method returns `unsupportedCapability`. The
checked-in subprocess does not advertise provider dispatch, value movement, or
browser integration.

The service source now defines the atomic `hns_requestAccounts` join. Only an
explicit runtime account-selector capability may advertise it. After the
trusted approval, the runtime supplies one typed HNS account; the service
validates and encodes its minimized ID result before atomically persisting that
same ID in the approval-bound permission generation. `hns_accounts` is then a
service-owned projection of only those persisted IDs; both methods return the
IDs as ordered 32-character lowercase hexadecimal strings. Null or an empty
object are the only accepted parameters, and generic `wallet_requestPermissions`
cannot create Accounts authority. The checked-in subprocess still uses
`UnavailableRuntime`, advertises neither method, and has no concrete
`HnsWalletRuntime`/browser product adapter, so this source contract is not
product availability.

## Explicitly forbidden

The default website API rejects `eth_sendTransaction`, `eth_call`,
`eth_estimateGas`, `eth_sign`, `personal_sign`, `wallet_addEthereumChain`,
`wallet_switchEthereumChain`, `bitcoin_signPsbt`, `signRawTransaction`, seed or
private-key export, arbitrary filesystem/process/native-host operations, and
unknown methods. Marketplace actions are typed methods whose parameters are
reconstructed and verified by the wallet.

## Error posture

Unknown methods, forbidden methods, invalid params, oversized frames, insecure
origins, unauthorized capabilities, replays, request flooding, stale context,
stale approval, locked wallet, and unavailable module/backend are distinct
errors. Errors minimize account and policy disclosure.

The provider/ABI/service/host account-join tests are focused implementation
evidence only; installed-browser and concrete-runtime qualification remain
pending.
