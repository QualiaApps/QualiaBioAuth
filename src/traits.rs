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

//! The platform-independent interface.
//!
//! The application holds one value that implements [`AuthBoundKeyStore`] and asks it
//! three questions: is this platform able to do it, wrap the master key, and unwrap
//! it. Each backend answers with its own platform mechanism; the caller does not
//! choose between them.

use crate::key::MasterKey;
use crate::{Error, Result};

/// The platform mechanism behind one auth-bound store.
///
/// The identifier is written into the blob (see [`crate::format`]) and therefore must
/// never change for an existing backend: bytes written by an older build depend on it.
/// A new backend takes a new number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Android Keystore, with a `BiometricPrompt` `CryptoObject`.
    AndroidKeystore,
    /// Windows Hello through the Win32 WebAuthn `hmac-secret` extension.
    WindowsWebAuthn,
    /// Apple Secure Enclave with a `SecAccessControl` user-presence requirement.
    ///
    /// Reserved: no backend writes it yet.
    AppleSecureEnclave,
    /// The in-memory mock. Test-only; never written by a production backend.
    Mock,
}

impl Backend {
    /// Identifier written into the blob.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Mock => 0,
            Self::AndroidKeystore => 1,
            Self::WindowsWebAuthn => 2,
            Self::AppleSecureEnclave => 3,
        }
    }

    /// Maps a blob identifier to a backend.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownBackend`] for an identifier this build does not know. Rejecting
    /// is deliberate: an unknown backend means the wrapped bytes have a layout this
    /// build cannot parse.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Mock),
            1 => Ok(Self::AndroidKeystore),
            2 => Ok(Self::WindowsWebAuthn),
            3 => Ok(Self::AppleSecureEnclave),
            other => Err(Error::UnknownBackend { backend: other }),
        }
    }

    /// Stable human-readable name, used in diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::AndroidKeystore => "android-keystore",
            Self::WindowsWebAuthn => "windows-webauthn",
            Self::AppleSecureEnclave => "apple-secure-enclave",
        }
    }
}

/// What a store can do on this machine, asked **before** the user is offered the
/// biometric path.
///
/// The three cases are deliberately distinct:
///
/// - [`Availability::Available`]: the platform mechanism works. `hardware_backed`
///   states what the platform actually reported — it must not be guessed.
/// - [`Availability::Unavailable`]: the platform has the mechanism, but this machine or
///   this user cannot use it right now (no Windows Hello enrolment, a removed
///   fingerprint, an Android version below 28). The password path must be used.
/// - [`Availability::Unsupported`]: this build has no backend for the platform at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// The platform can create and use an authentication-bound key.
    Available {
        /// Which mechanism answered.
        backend: Backend,
        /// Whether the platform reported hardware protection, rather than software.
        hardware_backed: bool,
    },
    /// The mechanism exists on this platform but cannot be used on this machine now.
    Unavailable {
        /// Fixed reason description, suitable for the user interface.
        reason: &'static str,
    },
    /// This build has no backend for this platform.
    Unsupported {
        /// Fixed reason description, suitable for the user interface.
        reason: &'static str,
    },
}

impl Availability {
    /// The backend, when one is available.
    #[must_use]
    pub const fn backend(self) -> Option<Backend> {
        match self {
            Self::Available { backend, .. } => Some(backend),
            Self::Unavailable { .. } | Self::Unsupported { .. } => None,
        }
    }

    /// Whether the biometric path may be offered to the user.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// A store whose key is bound to the platform's user authentication.
///
/// # What a backend must guarantee
///
/// The wrapped bytes are encrypted with material that the **platform** releases only
/// after the user authenticates. A backend that asks for authentication and then
/// decrypts with a key the process already holds is not implementing this trait; it is
/// a user-interface prompt with no cryptographic effect.
///
/// # Threading
///
/// The store is `Send + Sync` because an application shares one instance between the
/// user interface and background work. A backend that uses a platform handle which is
/// not thread-safe must serialize its own calls; the trait does not permit returning
/// "busy" as a normal answer.
///
/// # Errors
///
/// Every method may return [`Error::Unavailable`] when the platform stops being usable
/// between two calls (the user removed the PIN, the credential was invalidated). That
/// is a state the caller reports and recovers from through the password path, not a
/// crash.
pub trait AuthBoundKeyStore: core::fmt::Debug + Send + Sync {
    /// Reports what this store can do on this machine, without prompting.
    fn availability(&self) -> Availability;

    /// Creates the platform key or credential, prompting if the platform requires it.
    ///
    /// Idempotent: calling it again when the material already exists is not an error.
    /// A backend whose key is created as part of [`AuthBoundKeyStore::wrap`] may
    /// implement this as a no-op.
    fn create(&self) -> Result<()>;

    /// Wraps `master` and returns the **complete** blob, magic included.
    ///
    /// The returned bytes are what the application writes (for Qualia2FA,
    /// `master.key.bio`). They are not secret — without the platform key they open
    /// nothing — but they must not be logged: a copied blob is still a target.
    ///
    /// This may prompt: on Windows the Hello gesture releases the `hmac-secret` used
    /// as the wrapping key, and on Android the first use of an auth-required key needs
    /// the `CryptoObject`.
    fn wrap(&self, master: &MasterKey) -> Result<Vec<u8>>;

    /// Authenticates the user and unwraps the master key from `blob`.
    ///
    /// The blob is the complete output of [`AuthBoundKeyStore::wrap`]. A blob from
    /// another backend is rejected with [`Error::WrongBackend`] rather than parsed.
    fn unwrap(&self, blob: &[u8]) -> Result<MasterKey>;

    /// Deletes the platform key or credential named by `blob`.
    ///
    /// Used when the application turns the second path off after a restart: the blob is
    /// still on disk, but the store no longer remembers the credential it names. A backend
    /// whose platform material is fixed (one alias per device) may implement this as
    /// [`AuthBoundKeyStore::delete`]. A blob from another backend is rejected with
    /// [`Error::WrongBackend`] rather than deleting this backend's unrelated credential.
    fn delete_blob(&self, blob: &[u8]) -> Result<()>;

    /// Deletes the platform key or credential.
    ///
    /// Idempotent: deleting a store that holds nothing succeeds. The application is
    /// responsible for deleting the blob file; a blob whose platform material is gone
    /// simply stops unwrapping.
    fn delete(&self) -> Result<()>;
}
