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

//! Error types.
//!
//! Every public function returns [`Result`], and **no input may cause a panic**.
//!
//! # Secret-handling discipline
//!
//! Error values **never carry key material**: no master key bytes, no wrapped bytes,
//! no platform secret. Variants record which class of operation failed and the
//! non-secret numbers needed to locate the problem (lengths, backend identifiers).

use crate::traits::Backend;
use thiserror::Error;

/// The unified error type of this library.
///
/// The enum is `#[non_exhaustive]`, so a `match` outside this crate must have a
/// wildcard arm, and adding a variant is not a breaking change for downstream code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The auth-bound blob is structurally invalid.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("invalid auth-bound blob: {reason}")]
    Malformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The blob's format version is not supported.
    ///
    /// A future version must be rejected outright rather than interpreted under this
    /// version's layout.
    #[error("unsupported auth-bound blob version: {version}")]
    UnsupportedVersion {
        /// Version declared in the blob.
        version: u8,
    },

    /// The blob names a backend this build does not know.
    ///
    /// This is different from [`Error::WrongBackend`]: the blob is well-formed but
    /// names a platform whose wrapped-bytes layout is unknown here.
    #[error("the auth-bound blob names an unknown backend: {backend}")]
    UnknownBackend {
        /// Backend identifier from the blob.
        backend: u8,
    },

    /// The blob was written by a different backend than the one asked to open it.
    ///
    /// A Windows blob cannot be opened by the Android backend and vice versa. Reporting
    /// the mismatch instead of trying anyway keeps a corrupted or copied file from
    /// reaching a parser that would misread its payload.
    #[error("the auth-bound blob belongs to backend {actual:?}, but {expected:?} was asked")]
    WrongBackend {
        /// Backend that was asked to open the blob.
        expected: Backend,
        /// Backend recorded in the blob.
        actual: Backend,
    },

    /// The wrapped payload is too long for the format.
    #[error("the wrapped payload is {actual} bytes; at most {limit} are allowed")]
    PayloadTooLong {
        /// Declared length.
        actual: u32,
        /// Maximum the format accepts.
        limit: u32,
    },

    /// The wrapped payload is empty.
    #[error("the wrapped payload is empty")]
    PayloadEmpty,

    /// A master key has the wrong length.
    #[error("the master key must be {expected} bytes, but is {actual} bytes")]
    MasterKeyWrongLength {
        /// Required length.
        expected: usize,
        /// Length that was given.
        actual: usize,
    },

    /// The platform cannot provide an authentication-bound key right now.
    ///
    /// This is a **reported state**, not a bug: a machine without Windows Hello, an
    /// Android device below API 28, or a platform with no backend at all. The caller
    /// must keep the password path available and tell the user the truth; it must not
    /// silently fall back to a software key.
    #[error("this platform cannot provide an authentication-bound key: {reason}")]
    Unavailable {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The user cancelled the platform authentication, or it failed.
    ///
    /// This is **not** an error to report as "the key is broken": the user may simply
    /// have pressed back. The caller returns to the password path.
    #[error("the platform authentication did not succeed")]
    AuthenticationFailed,

    /// The platform's wrapped payload is not one this build can read.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("the platform's wrapped payload is invalid: {reason}")]
    WrappedPayloadInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// A platform call failed with a status code.
    ///
    /// The code is recorded for diagnosis; it is never a secret. The operation name is
    /// a fixed string chosen at the call site.
    #[error("platform operation {operation} failed with code {code}")]
    Platform {
        /// Operation that failed.
        operation: &'static str,
        /// Platform status code (HRESULT, JNI exception state, ...).
        code: i32,
    },

    /// The operating system refused to provide secure random bytes.
    #[error("cannot obtain secure random bytes from the operating system")]
    RandomnessUnavailable,

    /// The mock backend's payload did not authenticate.
    ///
    /// Kept separate from [`Error::AuthenticationFailed`] because it means "the test
    /// blob is damaged or came from another mock store", not "the user cancelled".
    #[error("the mock payload did not authenticate")]
    MockAuthenticationFailed,
}

/// The result type of this library.
pub type Result<T> = core::result::Result<T, Error>;
