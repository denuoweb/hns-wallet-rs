# Private wallet service ABI v2

ABI v2 is a deliberate replacement for the unreleased v1 value decoder. There
is no v1 compatibility decoder and no byte-vector origin context. Existing
browser manifests that require v1 must continue to report the provider
unavailable until a coordinated released v2 artifact is installed.

Every frame is exactly one four-byte big-endian payload length followed by one
strict JSON object. Unknown fields, empty frames, trailing bytes, partial
frames, and declared payloads over 1 MiB are rejected. The length is checked
before payload allocation. Provider requests are at most 64 KiB, provider
results 256 KiB, provider events 64 KiB, and approval prompts 16 KiB.

The first frame is a host hello containing:

- ABI version 2;
- a random 256-bit host-session ID;
- a nonzero restart generation, monotonic within that host session; and
- the exact platform transport.

The service responds with a fresh random 256-bit service-session ID. Subsequent
frames bind both IDs, the restart generation, a monotonic directional channel
sequence, and a canonical request ID. A new service process therefore rejects
every old request even if a numeric restart generation is accidentally reused.
All service IDs use fixed-length, unpadded base64url JSON strings, reject the
all-zero sentinel and noncanonical trailing bits, and redact `Debug`/`Display`.
Persisted wallet IDs retain their existing serialization.

## Authority control

Authority registration is accepted only over the private host/service pipe.
The browser host issues a random opaque handle and registers engine-derived
facts: logical origin, namespace, runtime session/generation, policy and
navigation generations, decision fingerprint, and expiry. Registration itself
is affirmative; there are no authentication/injection booleans. The service
never receives an engine authority object and does not reproduce engine policy.

Register, exact-revision replace, and exact-revision revoke operations own the
handle lifecycle. Provider and approval frames contain only the handle and its
service-owned revision. They contain no origin assertion, wallet lock/session,
permission generation, browser authority JSON, or capability secret supplied
by a page. Handles, approvals, replay windows, request IDs, rate state, and
event cursors are process-ephemeral.

## Approvals and events

Approval expiry is Unix milliseconds with a maximum lifetime of 90,000 ms.
Free-form display lines are forbidden. The closed approval union covers
permissions, module enablement, send, name transfer/finalize, typed signature,
name offer/purchase, market intent/fill, and swap redeem/refund. Value summaries
carry integer asset amounts, maximum fee, recipient, chain/finality and, where
applicable, price round and refund time. An incomplete or kind-mismatched
summary fails closed. Recovery-phrase display is not a provider/service
operation.

Events are typed frames bound to host/service/restart sessions, the exact
authority handle/revision, a monotonic service channel sequence, and a
per-authority event sequence. Bounded collection and string limits are checked
before encoding.

## Capability posture

Capabilities are a closed enum. Unsupported operations return the typed
`unsupportedCapability` failure and are never inferred from compiled source.
The checked-in subprocess runtime advertises framing/restart/registry/
structured-prompt/event foundations only. It does not advertise provider
dispatch, wallet operations, value movement, or browser integration. The
library can be composed with `WalletStore` for encrypted permission persistence,
but availability remains false until released runtimes and browser adapters
complete their independent gates.

The subprocess reads and writes v2 frames on inherited standard streams. A
production Chromium launcher must supply private child pipes and a separately
released signed artifact. Mobile may drive the same state machine in process
after generated JNI/C bindings exist. Filesystem paths, process commands, raw
signing, recovery output, private keys, database keys, preimages, and arbitrary
contract calls are absent from the protocol.
