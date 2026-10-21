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

//! A store for platforms where this build has no backend.
//!
//! It answers every operation with [`Error::Unavailable`] and deletes nothing, which
//! is the truthful state: there is no key to delete and no way to create one. The
//! application keeps the password path available.

use crate::key::MasterKey;
use crate::traits::{AuthBoundKeyStore, Availability};
use crate::{Error, Result};

/// A store that reports the platform as unsupported.
///
/// The reason is a fixed string chosen by the platform selection code, suitable for
/// the user interface ("this build has no Android Keystore backend", for example).
#[derive(Debug, Clone, Copy)]
pub struct UnsupportedKeyStore {
    /// Why this platform is unsupported.
    reason: &'static str,
}

impl UnsupportedKeyStore {
    /// Creates a store that reports `reason`.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// The reason this store reports.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl AuthBoundKeyStore for UnsupportedKeyStore {
    fn availability(&self) -> Availability {
        Availability::Unsupported {
            reason: self.reason,
        }
    }

    fn create(&self) -> Result<()> {
        Err(Error::Unavailable {
            reason: self.reason,
        })
    }

    fn wrap(&self, _master: &MasterKey) -> Result<Vec<u8>> {
        Err(Error::Unavailable {
            reason: self.reason,
        })
    }

    fn unwrap(&self, _blob: &[u8]) -> Result<MasterKey> {
        Err(Error::Unavailable {
            reason: self.reason,
        })
    }

    fn delete(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store reports itself as unsupported and refuses every operation.
    #[test]
    fn every_operation_reports_unavailable() {
        let store = UnsupportedKeyStore::new("no backend in this build");
        assert_eq!(
            store.availability(),
            Availability::Unsupported {
                reason: "no backend in this build",
            }
        );
        assert!(matches!(
            store.create(),
            Err(Error::Unavailable {
                reason: "no backend in this build"
            })
        ));
        let master = MasterKey::from_array([1_u8; crate::MASTER_KEY_LEN]);
        assert!(store.wrap(&master).is_err());
        assert!(store.unwrap(&[0_u8; 32]).is_err());
        assert!(store.delete().is_ok());
    }
}
