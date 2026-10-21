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

//! The 32-byte key this library wraps.
//!
//! The type is local on purpose: `qualia-bioauth` does not depend on
//! `qualia2fa-core`, so it can be used by any project that needs "a 32-byte secret
//! released only after platform authentication". The application converts its own
//! key type into a [`MasterKey`] at the boundary.

use crate::{Error, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Length of the key this library wraps.
pub const MASTER_KEY_LEN: usize = 32;

/// A 32-byte key whose bytes are wiped when it is dropped.
///
/// # Not `Copy` and not printable
///
/// The type deliberately does not implement `Copy`: a copy is one more place a secret
/// can outlive its use. `Debug` prints only the type and the length, so an accidental
/// `{:?}` cannot put key material in a log.
#[derive(Clone)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Wraps an existing 32-byte value.
    ///
    /// The bytes are copied into the new value; the caller's buffer is its own
    /// responsibility and should be wiped.
    #[must_use]
    pub const fn from_array(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies a slice into a key.
    ///
    /// # Errors
    ///
    /// [`Error::MasterKeyWrongLength`] unless the slice is exactly [`MASTER_KEY_LEN`]
    /// bytes. The value is rejected rather than padded or truncated.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MASTER_KEY_LEN {
            return Err(Error::MasterKeyWrongLength {
                expected: MASTER_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let mut key = [0_u8; MASTER_KEY_LEN];
        key.copy_from_slice(bytes);
        let value = Self(key);
        key.zeroize();
        Ok(value)
    }

    /// Generates a random key from the operating system's CSPRNG.
    ///
    /// This exists for tests and for the mock backend. A production caller already has
    /// a master key (from its vault format) and should use
    /// [`MasterKey::from_array`] or [`MasterKey::from_bytes`] instead.
    ///
    /// # Errors
    ///
    /// [`Error::RandomnessUnavailable`] when the operating system refuses to provide
    /// random bytes.
    #[cfg(any(test, feature = "mock"))]
    pub fn generate() -> Result<Self> {
        let mut key = [0_u8; MASTER_KEY_LEN];
        getrandom::fill(&mut key).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(key))
    }

    /// The key bytes.
    ///
    /// The borrow is the caller's to keep short. Do not copy these bytes into `String`,
    /// `Vec` or a log line: the only reason they are reachable is to hand them to the
    /// wrapping crypto.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    /// Constant-time equality.
    ///
    /// Used where two unlocks are compared (for example "the password wrap and the
    /// platform wrap must yield the same key"). A short-circuiting `==` would leak how
    /// many leading bytes matched.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MasterKey")
            .field("len", &MASTER_KEY_LEN)
            .finish_non_exhaustive()
    }
}

impl PartialEq for MasterKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for MasterKey {}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key generated twice differs.
    #[test]
    fn generation_is_random() {
        let a = MasterKey::generate().expect("randomness");
        let b = MasterKey::generate().expect("randomness");
        assert!(!a.ct_eq(&b), "two generated keys are equal");
    }

    /// `from_bytes` accepts exactly 32 bytes and rejects everything else.
    #[test]
    fn from_bytes_checks_the_length() {
        assert!(MasterKey::from_bytes(&[7_u8; MASTER_KEY_LEN]).is_ok());
        for length in [0_usize, 1, MASTER_KEY_LEN - 1, MASTER_KEY_LEN + 1] {
            assert!(
                matches!(
                    MasterKey::from_bytes(&vec![7_u8; length]),
                    Err(Error::MasterKeyWrongLength { .. })
                ),
                "length {length} must be rejected"
            );
        }
    }

    /// The key round trips through the constructor.
    #[test]
    fn from_bytes_preserves_the_value() {
        let source = [0x5A_u8; MASTER_KEY_LEN];
        let key = MasterKey::from_bytes(&source).expect("correct length");
        assert_eq!(key.expose_secret(), &source);
    }

    /// Constant-time equality still says the right thing.
    #[test]
    fn equality_compares_all_bytes() {
        let a = MasterKey::from_array([1_u8; MASTER_KEY_LEN]);
        let b = MasterKey::from_array([1_u8; MASTER_KEY_LEN]);
        let mut c = [1_u8; MASTER_KEY_LEN];
        c[MASTER_KEY_LEN - 1] = 2;
        let c = MasterKey::from_array(c);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// `Debug` does not print the key bytes.
    #[test]
    fn debug_never_prints_the_key() {
        let key = MasterKey::from_array([0xAB_u8; MASTER_KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("AB"));
        assert!(!rendered.contains("ab"));
        assert!(rendered.contains("MasterKey"));
    }
}
