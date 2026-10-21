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

//! An in-memory backend for tests of the format, the trait and the application flow.
//!
//! # This is not a user-authentication mechanism
//!
//! [`MockKeyStore`] encrypts with a key held in the same process and asks nobody for
//! anything. It exists so that tests do not need a TPM, a fingerprint or a Windows
//! Hello enrolment. It must never be reachable from a production build except through
//! the explicit `mock` feature, and it reports [`Backend::Mock`] so that its blobs
//! cannot be mistaken for a real backend's.
//!
//! # Payload
//!
//! ```text
//!   nonce (24) | XChaCha20-Poly1305 ciphertext of the 32-byte key + tag (48)
//! ```
//!
//! The AAD is a fixed domain string, so a payload from another mock store — or from a
//! future version with a different layout — fails authentication.

use crate::format::AuthBlob;
use crate::key::{MASTER_KEY_LEN, MasterKey};
use crate::traits::{AuthBoundKeyStore, Availability, Backend};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroize;

/// Nonce length of XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// Authentication tag length.
const TAG_LEN: usize = 16;

/// AAD bound into every mock payload.
const AAD: &[u8] = b"qualia-bioauth mock v1";

/// Length of a mock payload: nonce, ciphertext and tag.
const PAYLOAD_LEN: usize = NONCE_LEN + MASTER_KEY_LEN + TAG_LEN;

/// A software auth-bound store for tests.
///
/// The "platform key" is a random 32-byte value kept in memory and wiped by
/// [`AuthBoundKeyStore::delete`] and by `Drop`. Cloning the store is deliberately not
/// possible: a clone would be a second copy of the key.
pub struct MockKeyStore {
    /// The wrapping key, or `None` before the first use and after a delete.
    kek: Mutex<Option<[u8; 32]>>,
}

impl MockKeyStore {
    /// Creates an empty store.
    ///
    /// The wrapping key is generated on the first [`AuthBoundKeyStore::create`] or
    /// [`AuthBoundKeyStore::wrap`] call, so construction cannot fail.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kek: Mutex::new(None),
        }
    }

    /// Runs `operation` with the wrapping key, generating it if necessary.
    fn with_key<T>(&self, operation: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        let mut guard = self.kek.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|_| Error::RandomnessUnavailable)?;
            *guard = Some(key);
        }
        let key = guard.as_ref().expect("the key was just generated");
        operation(key)
    }

    /// Whether a wrapping key exists.
    fn has_key(&self) -> bool {
        self.kek
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

impl Default for MockKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for MockKeyStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MockKeyStore")
            .field("has_key", &self.has_key())
            .finish_non_exhaustive()
    }
}

impl AuthBoundKeyStore for MockKeyStore {
    fn availability(&self) -> Availability {
        Availability::Available {
            backend: Backend::Mock,
            hardware_backed: false,
        }
    }

    fn create(&self) -> Result<()> {
        self.with_key(|_| Ok(()))
    }

    fn wrap(&self, master: &MasterKey) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; NONCE_LEN];
        let ciphertext = self.with_key(|key| {
            getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
            let cipher = XChaCha20Poly1305::new(&Key::from(*key));
            cipher
                .encrypt(
                    &XNonce::from(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: master.expose_secret(),
                        aad: AAD,
                    },
                )
                .map_err(|_| Error::Platform {
                    operation: "mock encrypt",
                    code: 0,
                })
        })?;

        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        AuthBlob::new(Backend::Mock, payload).map(|blob| blob.encode())
    }

    fn unwrap(&self, blob: &[u8]) -> Result<MasterKey> {
        let blob = AuthBlob::parse(blob)?;
        blob.expect_backend(Backend::Mock)?;
        let payload = blob.wrapped();
        if payload.len() != PAYLOAD_LEN {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the mock payload does not have the fixed length",
            });
        }
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&payload[..NONCE_LEN]);

        let plaintext = self.with_key(|key| {
            let cipher = XChaCha20Poly1305::new(&Key::from(*key));
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &payload[NONCE_LEN..],
                        aad: AAD,
                    },
                )
                .map_err(|_| Error::MockAuthenticationFailed)
        })?;
        if plaintext.len() != MASTER_KEY_LEN {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the mock payload does not decrypt to a 32-byte key",
            });
        }
        let mut key = [0_u8; MASTER_KEY_LEN];
        key.copy_from_slice(&plaintext);
        let value = MasterKey::from_array(key);
        key.zeroize();
        Ok(value)
    }

    fn delete(&self) -> Result<()> {
        let mut guard = self.kek.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(mut key) = guard.take() {
            key.zeroize();
        }
        Ok(())
    }
}

impl Drop for MockKeyStore {
    fn drop(&mut self) {
        if let Some(mut key) = self
            .kek
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wrapped key opens to the same value.
    #[test]
    fn wrap_unwrap_roundtrip() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let blob = store.wrap(&master).expect("wrap");
        assert_eq!(blob.len(), crate::format::HEADER_LEN + PAYLOAD_LEN);
        let restored = store.unwrap(&blob).expect("unwrap");
        assert_eq!(restored, master);
    }

    /// Two wraps of the same key differ (the nonce is fresh).
    #[test]
    fn two_wraps_differ() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let a = store.wrap(&master).expect("wrap");
        let b = store.wrap(&master).expect("wrap");
        assert_ne!(a, b);
        assert_eq!(store.unwrap(&a).expect("a"), master);
        assert_eq!(store.unwrap(&b).expect("b"), master);
    }

    /// A blob from another mock store does not authenticate.
    #[test]
    fn another_store_cannot_unwrap() {
        let first = MockKeyStore::new();
        let second = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let blob = first.wrap(&master).expect("wrap");
        assert!(matches!(
            second.unwrap(&blob),
            Err(Error::MockAuthenticationFailed)
        ));
    }

    /// Flipping a byte of the payload is detected.
    #[test]
    fn payload_tampering_is_detected() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let mut blob = store.wrap(&master).expect("wrap");
        for index in crate::format::HEADER_LEN..blob.len() {
            let original = blob[index];
            blob[index] ^= 0x01;
            assert!(
                store.unwrap(&blob).is_err(),
                "flipping byte {index} was not detected"
            );
            blob[index] = original;
        }
    }

    /// Offset of the backend byte in the outer header.
    const BACKEND_OFFSET: usize = 9;

    /// The outer header is still checked before the payload.
    #[test]
    fn wrong_backend_is_rejected() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let mut blob = store.wrap(&master).expect("wrap");
        blob[BACKEND_OFFSET] = 2;
        assert!(matches!(
            store.unwrap(&blob),
            Err(Error::WrongBackend {
                expected: Backend::Mock,
                actual: Backend::WindowsWebAuthn,
            })
        ));
    }

    /// After a delete the old blob stops opening and a new key starts over.
    #[test]
    fn delete_wipes_the_key() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let blob = store.wrap(&master).expect("wrap");
        store.delete().expect("delete");
        assert!(!store.has_key());
        assert!(store.unwrap(&blob).is_err());

        let fresh = MasterKey::generate().expect("randomness");
        let new_blob = store.wrap(&fresh).expect("wrap after delete");
        assert_eq!(store.unwrap(&new_blob).expect("unwrap"), fresh);
    }

    /// `create` is idempotent and leaves the existing key alone.
    #[test]
    fn create_is_idempotent() {
        let store = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let blob = store.wrap(&master).expect("wrap");
        store.create().expect("create");
        store.create().expect("create again");
        assert_eq!(store.unwrap(&blob).expect("unwrap"), master);
    }

    /// Availability reports the mock backend and no hardware protection.
    #[test]
    fn availability_is_honest() {
        let store = MockKeyStore::new();
        assert_eq!(
            store.availability(),
            Availability::Available {
                backend: Backend::Mock,
                hardware_backed: false,
            }
        );
    }

    /// `Debug` does not print the key.
    #[test]
    fn debug_does_not_print_the_key() {
        let store = MockKeyStore::new();
        store.create().expect("create");
        let rendered = format!("{store:?}");
        assert!(rendered.contains("has_key"));
        assert!(!rendered.contains("ab"));
    }
}
