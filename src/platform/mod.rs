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

//! Platform backends.
//!
//! Each backend lives behind its own `cfg`, so a build for one platform does not
//! compile another platform's FFI. The common trait is in [`crate::traits`].
//!
//! # Current state
//!
//! - `windows`: Windows Hello through the Win32 WebAuthn `hmac-secret` extension.
//! - [`stub`]: the honest "this build cannot do it" backend, used everywhere a real
//!   backend is not wired yet.
//! - Android Keystore is planned. Its design is fixed by the rule that the
//!   **platform** must release the key: a prompt whose success is only checked in
//!   user-mode is not a backend.
//!
//! A platform without a backend must report [`crate::Availability::Unsupported`],
//! never a software key that pretends to be protected.

pub mod stub;

#[cfg(target_os = "windows")]
pub mod windows;

use crate::traits::AuthBoundKeyStore;

/// Opens the best auth-bound store this build has for the current platform.
///
/// The returned value always exists; ask [`AuthBoundKeyStore::availability`] before
/// offering the platform-authentication path. On a platform without a backend this is
/// [`stub::UnsupportedKeyStore`], which reports the truth and refuses every operation.
///
/// The store holds no credential until it is used, so calling this at startup does not
/// prompt and does not touch the platform.
#[must_use]
pub fn open_best_available() -> Box<dyn AuthBoundKeyStore> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsKeyStore::new())
    }

    #[cfg(not(target_os = "windows"))]
    {
        Box::new(stub::UnsupportedKeyStore::new(
            "this build has no auth-bound key backend for this platform",
        ))
    }
}
