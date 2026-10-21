# QualiaBioAuth

Chinese version: [README.md](README.md).

`qualia-bioauth` is an independent library: it wraps a 32-byte key into bytes that can
only be opened after the platform has authenticated the user. It knows nothing about
the Qualia2FA vault format, its protocol, or its core library, so any project that
needs this kind of protection can use it.

## What it solves

A password wrap protects a key, but a password can be guessed, shoulder-surfed or
reused. This library adds the other way in: the platform itself holds the key that
opens the wrap.

- **Android**: an AES key in the Keystore with `setUserAuthenticationRequired(true)`.
  Unwrapping uses the `Cipher` inside a `BiometricPrompt` `CryptoObject`, not a
  "prompt succeeded, now decrypt without a gate" callback.
- **Windows**: the `hmac-secret` (WebAuthn PRF) output of a Windows Hello credential.
  Only a completed Hello gesture releases it; its 32 bytes are the wrapping key.
- **Apple**: reserved for a Secure Enclave key with `.userPresence`; not implemented.
- **Linux**: no backend; it reports `Unsupported` truthfully.

The two wraps are independent: either one opens the same key, so a forgotten password
or a re-enrolled fingerprint does not lock the user out. When neither works the
application fails closed; it never falls back to a software key.

## Status

0.1.0 implements the Windows backend; the Android backend is not in yet:

- the outer `Q2FABIO1` format (magic, version, backend, length, backend-private
  payload);
- `MasterKey` (32 bytes, `Zeroize`, `Debug` prints nothing);
- the `AuthBoundKeyStore` trait and `Availability`;
- the test-only `MockKeyStore` (`mock` feature) and the honest
  `UnsupportedKeyStore`;
- the **Windows backend**: a Windows Hello credential plus WebAuthn `hmac-secret`,
  whose platform-released 32 bytes are the wrapping key.

The Windows backend requires the platform authenticator to actually return `hmac-secret` in
`GetAssertion`. The attestation's `bPrfEnabled` is **not** the criterion: Windows 11 23H2
creates the credential and leaves that field at zero. The crate does not trust it; the first
assertion is the test — a 32-byte secret means it works, a refusal **or an assertion without
the secret** means `Unavailable`. A browser PRF demo succeeding is therefore not proof for
the native Win32 API; acceptance has to run this crate's `hello_probe`.

The WebAuthn API version picks the structure as well: an API 9 runtime (Windows 11 25H2)
rejects the version 7 `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS` with
`NTE_INVALID_PARAMETER`, so the version 9 layout is required, where `pPRFGlobalEval` is the
creation-time PRF entry. The crate selects the layout by `WebAuthNGetApiVersionNumber` and
pins the structure size with a compile-time assertion on x64.

**Windows L3 acceptance has passed** (API 9; `create`, `wrap`, `unwrap` and `delete` all
succeeded: `RESULT: roundtrip OK`). Three conditions decide the run and each of them
produces a misleading error code when missing: a process image on a local disk, a non-null
parent window, and a Windows build whose platform authenticator enables PRF.

The Android Keystore backend is still being implemented. **Until it lands, do not treat
this crate as one that provides platform authentication on Android**; `availability()`
reports `Unsupported` there.

## Usage

```toml
[dependencies]
qualia-bioauth = { version = "0.1", features = ["mock"] }
```

```rust
use qualia_bioauth::{AuthBoundKeyStore, Availability, MasterKey, mock::MockKeyStore};

let store = MockKeyStore::new();
if store.availability().is_available() {
    let master = MasterKey::from_bytes(&[7_u8; 32]).expect("32 bytes");
    let blob = store.wrap(&master).expect("wrap");
    let restored = store.unwrap(&blob).expect("unwrap");
    assert_eq!(restored, master);
}
```

A real backend is used the same way: hold a value implementing
`AuthBoundKeyStore`, ask `availability()` before offering the path to the user, then
call `wrap` / `unwrap`.

## Integration rules

- The library does **no I/O**: `wrap` returns a complete outer blob and the caller
  decides where it lives.
- It does **not depend on `qualia2fa-core`**: the 32-byte key type is local, and the
  application converts at the boundary.
- The platform payload is private; the outer format only validates magic, version,
  backend and length.
- No input may cause a panic; error messages and `Debug` contain no key material or
  payload bytes.
- `unsafe` is allowed only in platform backends, and every block states its invariant
  under `// SAFETY:`; CI raises `undocumented_unsafe_blocks` to an error.

## Contributing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --features mock -- -D warnings
cargo test --all-targets --features mock
cargo test --doc --features mock
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo deny check
```

Each platform backend needs real-device verification on Windows and Android. Without
a device, `Availability` must report `Unavailable` or `Unsupported`; it must not
pretend to be usable.

## License

GNU Lesser General Public License v3.0 or later (`LGPL-3.0-or-later`). The complete
texts are in [COPYING.LESSER](COPYING.LESSER) and [LICENSE](LICENSE).
