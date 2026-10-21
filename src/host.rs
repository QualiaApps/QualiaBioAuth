// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! A store whose platform half is supplied by the host application.
//!
//! # Why the platform half is not here
//!
//! Android's auth-bound key lives in the Android Keystore, and using it requires a
//! `BiometricPrompt` attached to an `Activity`'s UI thread. Neither is reachable from a
//! library: the `Activity` belongs to the application, the prompt must run on the main
//! looper, and a blocked library call cannot host it. The same shape appears on any
//! platform whose user-verification UI is owned by the application rather than by an API
//! that blocks until the gesture is done.
//!
//! So the split is: this crate owns the **format**, the **key type**, the **error
//! taxonomy** and the ordering of operations; the host owns the **platform calls**
//! (keystore key generation, the prompt, the cipher). The host implements
//! [`PlatformSealer`], which is allowed to prompt and to block until the gesture is done.
//!
//! # What the host must guarantee
//!
//! - [`PlatformSealer::seal`] returns bytes that only the same platform key can open. A
//!   software copy of the key, or a "seal" that is plain encryption with a key the host
//!   also keeps, defeats the purpose and is **not** a conforming implementation.
//! - [`PlatformSealer::unseal`] performs user verification. It must fail with
//!   [`crate::Error::AuthenticationFailed`] when the user cancels, and must never return bytes it
//!   could not authenticate.
//! - [`PlatformSealer::delete`] removes the platform key. Idempotent.
//!
//! The crate cannot verify the first guarantee; it can only keep the envelope honest about
//! which backend produced it, so that a blob from a different backend is refused rather
//! than fed to a sealer that would misread it.

use crate::Result;
use crate::format::AuthBlob;
use crate::key::MasterKey;
use crate::traits::{AuthBoundKeyStore, Availability, Backend};
use std::sync::Arc;

/// The platform half of an auth-bound key store, implemented by the host application.
///
/// Every method may prompt. The crate never calls them while holding a lock of its own, so
/// a prompt that blocks for as long as the user takes is fine.
pub trait PlatformSealer: core::fmt::Debug + Send + Sync {
    /// Which backend these bytes belong to. Recorded in the blob and checked on the way in.
    fn backend(&self) -> Backend;

    /// Reports whether the platform can seal right now, without prompting.
    fn availability(&self) -> Availability;

    /// Seals `plaintext` with the platform key, prompting if the platform requires it.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Unseals `envelope`, performing user verification.
    ///
    /// Must return [`crate::Error::AuthenticationFailed`] when the user cancels, and must not
    /// return bytes whose authenticity it could not establish.
    fn unseal(&self, envelope: &[u8]) -> Result<Vec<u8>>;

    /// Deletes the platform key. Idempotent.
    fn delete(&self) -> Result<()>;
}

/// An [`AuthBoundKeyStore`] whose platform calls are delegated to a [`PlatformSealer`].
///
/// The blob is the crate's own `Q2FABIO1` envelope around the host's bytes, so the backend
/// identifier and the length limits are enforced here rather than trusted from the host.
#[derive(Debug)]
pub struct DelegatingKeyStore {
    /// The host's platform half; every platform call goes through it.
    sealer: Arc<dyn PlatformSealer>,
}

impl DelegatingKeyStore {
    /// Builds a store over `sealer`.
    #[must_use]
    pub fn new(sealer: Arc<dyn PlatformSealer>) -> Self {
        Self { sealer }
    }
}

impl AuthBoundKeyStore for DelegatingKeyStore {
    fn availability(&self) -> Availability {
        self.sealer.availability()
    }

    fn create(&self) -> Result<()> {
        // The host generates its platform key as part of sealing: there is nothing to do
        // before the first prompt, and a prompt here would ask for a gesture the user has
        // not asked for yet.
        Ok(())
    }

    fn wrap(&self, master: &MasterKey) -> Result<Vec<u8>> {
        let envelope = self.sealer.seal(master.expose_secret())?;
        let blob = AuthBlob::new(self.sealer.backend(), envelope)?;
        Ok(blob.encode())
    }

    fn unwrap(&self, blob: &[u8]) -> Result<MasterKey> {
        let blob = AuthBlob::parse(blob)?;
        blob.expect_backend(self.sealer.backend())?;
        let plaintext = self.sealer.unseal(blob.wrapped())?;
        // `from_bytes` rejects any length other than 32, so a host that returns something
        // else is reported as a key-length error rather than padded or truncated.
        MasterKey::from_bytes(&plaintext)
    }

    fn delete_blob(&self, blob: &[u8]) -> Result<()> {
        let blob = AuthBlob::parse(blob)?;
        blob.expect_backend(self.sealer.backend())?;
        self.sealer.delete()
    }

    fn delete(&self) -> Result<()> {
        self.sealer.delete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::key::MASTER_KEY_LEN;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A sealer that XORs with a fixed pad, standing in for a platform key.
    #[derive(Debug, Default)]
    struct FakeSealer {
        present: AtomicBool,
        cancelled: AtomicBool,
        sealed: Mutex<Option<Vec<u8>>>,
    }

    impl PlatformSealer for FakeSealer {
        fn backend(&self) -> Backend {
            Backend::AndroidKeystore
        }

        fn availability(&self) -> Availability {
            Availability::Available {
                backend: Backend::AndroidKeystore,
                hardware_backed: true,
            }
        }

        fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(Error::AuthenticationFailed);
            }
            let sealed: Vec<u8> = plaintext.iter().map(|byte| byte ^ 0x5A).collect();
            *self.sealed.lock().expect("lock") = Some(sealed.clone());
            self.present.store(true, Ordering::SeqCst);
            Ok(sealed)
        }

        fn unseal(&self, envelope: &[u8]) -> Result<Vec<u8>> {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(Error::AuthenticationFailed);
            }
            if !self.present.load(Ordering::SeqCst) {
                return Err(Error::AuthenticationFailed);
            }
            Ok(envelope.iter().map(|byte| byte ^ 0x5A).collect())
        }

        fn delete(&self) -> Result<()> {
            self.present.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    fn store() -> (DelegatingKeyStore, Arc<FakeSealer>) {
        let sealer = Arc::new(FakeSealer::default());
        (DelegatingKeyStore::new(sealer.clone()), sealer)
    }

    /// The crate's envelope wraps the host bytes and carries the host's backend id.
    #[test]
    fn a_wrap_roundtrips_through_the_host() {
        let (store, sealer) = store();
        let master = MasterKey::from_bytes(&[7_u8; MASTER_KEY_LEN]).expect("master key");

        let blob = store.wrap(&master).expect("wrap");
        assert!(blob.starts_with(b"Q2FABIO1"));
        assert_eq!(
            AuthBlob::parse(&blob).expect("parse").backend(),
            Backend::AndroidKeystore
        );
        // The host bytes are inside the envelope, not equal to the master key.
        assert_ne!(&blob[blob.len() - MASTER_KEY_LEN..], master.expose_secret());
        assert!(sealer.present.load(Ordering::SeqCst));

        assert_eq!(store.unwrap(&blob).expect("unwrap"), master);
    }

    /// A cancelled gesture is reported as such and never yields a key.
    #[test]
    fn a_cancelled_gesture_is_authentication_failed() {
        let (store, sealer) = store();
        let master = MasterKey::from_bytes(&[1_u8; MASTER_KEY_LEN]).expect("master key");
        let blob = store.wrap(&master).expect("wrap");

        sealer.cancelled.store(true, Ordering::SeqCst);
        assert!(matches!(
            store.unwrap(&blob),
            Err(Error::AuthenticationFailed)
        ));
    }

    /// A blob from another backend is refused before the host is asked to open it.
    #[test]
    fn a_windows_blob_is_refused() {
        let (store, _sealer) = store();
        let blob = AuthBlob::new(Backend::WindowsWebAuthn, vec![1, 2, 3])
            .expect("blob")
            .encode();
        assert!(matches!(
            store.unwrap(&blob),
            Err(Error::WrongBackend { .. })
        ));
    }

    /// The host's bytes must be a 32-byte key; anything else is rejected, not padded.
    #[test]
    fn a_short_plaintext_is_rejected() {
        let sealer = Arc::new(FakeSealer::default());
        sealer.present.store(true, Ordering::SeqCst);
        let store = DelegatingKeyStore::new(sealer);
        let blob = AuthBlob::new(Backend::AndroidKeystore, vec![0_u8; 5])
            .expect("blob")
            .encode();
        assert!(matches!(
            store.unwrap(&blob),
            Err(Error::MasterKeyWrongLength { .. })
        ));
    }

    /// Deleting through a blob removes the platform key.
    #[test]
    fn delete_blob_removes_the_platform_key() {
        let (store, sealer) = store();
        let master = MasterKey::from_bytes(&[3_u8; MASTER_KEY_LEN]).expect("master key");
        let blob = store.wrap(&master).expect("wrap");
        store.delete_blob(&blob).expect("delete");
        assert!(!sealer.present.load(Ordering::SeqCst));
        assert!(store.unwrap(&blob).is_err());
    }

    /// `create` is a no-op: the platform key is generated by the first seal.
    #[test]
    fn create_does_not_prompt() {
        let (store, sealer) = store();
        store.create().expect("create");
        assert!(!sealer.present.load(Ordering::SeqCst));
    }
}
