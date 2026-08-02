# Wallet ABI v1

`hns-wallet-ffi` defines a stable JSON value ABI for Android, iOS, and the
Chromium native host. Transport adapters add their own length framing. Every
envelope binds ABI version, nonzero request ID, nonzero wallet session nonce,
and one typed operation. Frames, secret inputs, provider parameters, method
names, and origin-context stamps are bounded before dispatch.

The ABI contains typed status, create/restore, lock/unlock, account, balance,
receive, history, module, provider, approval, and workflow operations. It has no
filesystem/process command, private-key/seed byte response, raw-signing call,
arbitrary Ethereum calldata, PSBT signing, database-key response, HTLC-preimage
response, or native capability-token response.

Recovery-phrase display is the sole phrase-bearing response. It requires a
nonzero dedicated native UI confirmation nonce and is rejected unconditionally
on the Chromium native-host transport. Restore accepts a phrase as sensitive
input only; the page/provider surface cannot invoke restore.

The Rust value ABI and negative tests exist. JNI/Kotlin, Swift/C, and Chromium
host generated bindings plus compatibility fixtures across released browser
artifacts are not yet complete. ABI additions must be backward compatible;
breaking changes require a new version and parallel decoder during migration.
