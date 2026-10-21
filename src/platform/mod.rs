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
//! - [`stub`]: the honest "this build cannot do it" backend, used everywhere until a
//!   real backend is wired for that platform.
//! - Android Keystore and Windows WebAuthn are planned. Their design is fixed by the
//!   rule that the **platform** must release the key: a prompt whose success is only
//!   checked in user-mode is not a backend.
//!
//! A platform without a backend must report [`crate::Availability::Unsupported`],
//! never a software key that pretends to be protected.

pub mod stub;
