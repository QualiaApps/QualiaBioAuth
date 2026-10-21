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

//! The platform-neutral outer blob (`master.key.bio` in Qualia2FA).
//!
//! # What it is
//!
//! The backend's wrapped bytes are platform-specific and opaque to this module. The
//! outer blob adds just enough structure to answer three questions without knowing
//! that payload:
//!
//! 1. **Is this an auth-bound blob at all?** — the magic.
//! 2. **Which platform wrote it?** — the backend byte. Opening a blob with the wrong
//!    backend is rejected before its payload is parsed.
//! 3. **How long is the payload?** — a big-endian `u32`, checked against a limit
//!    before any allocation.
//!
//! # Format
//!
//! ```text
//!   offset  length  content
//!   0       8       magic `Q2FABIO1`
//!   8       1       format version (1)
//!   9       1       backend (1 Android, 2 Windows, 3 Apple, 0 mock)
//!   10      4       wrapped payload length, big-endian
//!   14      n       wrapped payload, 1 ..= 1024 bytes
//! ```
//!
//! The total length must be **exactly** `14 + n`: trailing bytes are rejected rather
//! than ignored, so a file that was appended to is not silently accepted.
//!
//! # What this format does not protect
//!
//! The payload is not secret — the platform key is what opens it — but it is also not
//! authenticated here. Each backend authenticates its own payload (AES-GCM on Android,
//! XChaCha20-Poly1305 on Windows); a damaged payload is rejected by the backend, not
//! by this module. The outer blob therefore carries no MAC of its own.

use crate::traits::Backend;
use crate::{Error, Result};

/// File magic.
const MAGIC: &[u8; 8] = b"Q2FABIO1";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum wrapped payload length.
///
/// A wrapped 32-byte key plus a nonce, a tag and a platform credential identifier is
/// well under 200 bytes; 1024 leaves room for a platform that stores more context
/// without letting a crafted file drive a large allocation.
pub const MAX_WRAPPED_LEN: usize = 1024;

/// Length of the fixed header.
pub const HEADER_LEN: usize = 14;

/// Maximum total blob length.
pub const MAX_BLOB_LEN: usize = HEADER_LEN + MAX_WRAPPED_LEN;

/// Offsets of the header fields.
mod offset {
    /// Start of the magic.
    pub const MAGIC: usize = 0;
    /// Format version.
    pub const VERSION: usize = 8;
    /// Backend identifier.
    pub const BACKEND: usize = 9;
    /// Wrapped payload length (big-endian u32).
    pub const LENGTH: usize = 10;
    /// Start of the wrapped payload.
    pub const PAYLOAD: usize = super::HEADER_LEN;
}

/// A parsed or constructed outer blob.
///
/// Construction validates the payload length, so `encode` cannot produce a blob that
/// `parse` would reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBlob {
    /// Which platform wrote the payload.
    backend: Backend,
    /// The platform's opaque wrapped bytes.
    wrapped: Vec<u8>,
}

impl AuthBlob {
    /// Builds a blob from a backend and its wrapped payload.
    ///
    /// # Errors
    ///
    /// - [`Error::PayloadEmpty`] for an empty payload
    /// - [`Error::PayloadTooLong`] above [`MAX_WRAPPED_LEN`]
    pub fn new(backend: Backend, wrapped: Vec<u8>) -> Result<Self> {
        if wrapped.is_empty() {
            return Err(Error::PayloadEmpty);
        }
        if wrapped.len() > MAX_WRAPPED_LEN {
            return Err(Error::PayloadTooLong {
                actual: wrapped.len() as u32,
                limit: MAX_WRAPPED_LEN as u32,
            });
        }
        Ok(Self { backend, wrapped })
    }

    /// Parses a complete blob.
    ///
    /// # Errors
    ///
    /// - wrong magic, length or trailing bytes: [`Error::Malformed`]
    /// - unknown version: [`Error::UnsupportedVersion`]
    /// - unknown backend identifier: [`Error::UnknownBackend`]
    /// - empty payload: [`Error::PayloadEmpty`]
    /// - payload above the limit: [`Error::PayloadTooLong`]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Malformed {
                reason: "the blob is shorter than its fixed header",
            });
        }
        if &bytes[offset::MAGIC..offset::VERSION] != MAGIC {
            return Err(Error::Malformed {
                reason: "magic mismatch: this is not an auth-bound blob",
            });
        }
        if bytes[offset::VERSION] != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                version: bytes[offset::VERSION],
            });
        }
        let backend = Backend::from_id(bytes[offset::BACKEND])?;
        let declared =
            u32::from_be_bytes(bytes[offset::LENGTH..offset::PAYLOAD].try_into().map_err(
                |_| Error::Malformed {
                    reason: "failed to read the wrapped payload length",
                },
            )?);
        if declared == 0 {
            return Err(Error::PayloadEmpty);
        }
        if declared as usize > MAX_WRAPPED_LEN {
            return Err(Error::PayloadTooLong {
                actual: declared,
                limit: MAX_WRAPPED_LEN as u32,
            });
        }
        let expected = HEADER_LEN
            .checked_add(declared as usize)
            .ok_or(Error::PayloadTooLong {
                actual: declared,
                limit: MAX_WRAPPED_LEN as u32,
            })?;
        if bytes.len() != expected {
            return Err(Error::Malformed {
                reason: "the blob length does not match the payload length it declares",
            });
        }
        let wrapped = bytes[offset::PAYLOAD..].to_vec();
        Ok(Self { backend, wrapped })
    }

    /// The backend that wrote the payload.
    #[must_use]
    pub const fn backend(&self) -> Backend {
        self.backend
    }

    /// The platform's opaque wrapped bytes.
    #[must_use]
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }

    /// Rejects a blob that was written by another backend.
    ///
    /// # Errors
    ///
    /// [`Error::WrongBackend`] when `self.backend` is not `expected`.
    pub fn expect_backend(&self, expected: Backend) -> Result<()> {
        if self.backend == expected {
            Ok(())
        } else {
            Err(Error::WrongBackend {
                expected,
                actual: self.backend,
            })
        }
    }

    /// Serializes the complete blob.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + self.wrapped.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(self.backend.id());
        bytes.extend_from_slice(&(self.wrapped.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.wrapped);
        debug_assert_eq!(bytes.len(), HEADER_LEN + self.wrapped.len());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample payload of the requested length.
    fn payload(length: usize) -> Vec<u8> {
        (0..length).map(|index| index as u8).collect()
    }

    /// Encoding and parsing restores the backend and the payload.
    #[test]
    fn encode_parse_roundtrip() {
        for backend in [
            Backend::AndroidKeystore,
            Backend::WindowsWebAuthn,
            Backend::AppleSecureEnclave,
            Backend::Mock,
        ] {
            let blob = AuthBlob::new(backend, payload(72)).expect("valid payload");
            let encoded = blob.encode();
            assert_eq!(encoded.len(), HEADER_LEN + 72);
            let parsed = AuthBlob::parse(&encoded).expect("valid blob");
            assert_eq!(parsed.backend(), backend);
            assert_eq!(parsed.wrapped(), blob.wrapped());
            assert_eq!(parsed, blob);
        }
    }

    /// The header layout is a public contract.
    #[test]
    fn layout_is_stable() {
        assert_eq!(HEADER_LEN, 14);
        assert_eq!(MAX_WRAPPED_LEN, 1024);
        assert_eq!(MAX_BLOB_LEN, 1038);
        assert_eq!(offset::MAGIC, 0);
        assert_eq!(offset::VERSION, 8);
        assert_eq!(offset::BACKEND, 9);
        assert_eq!(offset::LENGTH, 10);
        assert_eq!(offset::PAYLOAD, 14);
    }

    /// A wrong magic is reported as malformed.
    #[test]
    fn wrong_magic_is_rejected() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        encoded[0] = b'X';
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::Malformed { .. })
        ));
    }

    /// A future version is rejected explicitly.
    #[test]
    fn unknown_version_is_rejected() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        encoded[offset::VERSION] = 2;
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::UnsupportedVersion { version: 2 })
        ));
    }

    /// An unknown backend is rejected before the payload is read.
    #[test]
    fn unknown_backend_is_rejected() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        encoded[offset::BACKEND] = 0x7F;
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::UnknownBackend { backend: 0x7F })
        ));
    }

    /// A blob from another backend is rejected with the two backends named.
    #[test]
    fn wrong_backend_is_rejected() {
        let blob = AuthBlob::new(Backend::WindowsWebAuthn, payload(32)).expect("valid");
        assert!(matches!(
            blob.expect_backend(Backend::AndroidKeystore),
            Err(Error::WrongBackend {
                expected: Backend::AndroidKeystore,
                actual: Backend::WindowsWebAuthn,
            })
        ));
        assert!(blob.expect_backend(Backend::WindowsWebAuthn).is_ok());
    }

    /// Empty and oversized payloads cannot be constructed.
    #[test]
    fn payload_limits_are_enforced_on_construction() {
        assert!(matches!(
            AuthBlob::new(Backend::Mock, Vec::new()),
            Err(Error::PayloadEmpty)
        ));
        assert!(
            AuthBlob::new(Backend::Mock, payload(MAX_WRAPPED_LEN)).is_ok(),
            "the limit itself must be allowed"
        );
        assert!(matches!(
            AuthBlob::new(Backend::Mock, payload(MAX_WRAPPED_LEN + 1)),
            Err(Error::PayloadTooLong { .. })
        ));
    }

    /// A declared length of zero is rejected without allocating.
    #[test]
    fn zero_length_is_rejected() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        encoded[offset::LENGTH..offset::PAYLOAD].fill(0);
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::PayloadEmpty)
        ));
    }

    /// A length above the limit is rejected without allocating.
    #[test]
    fn oversized_declared_length_is_rejected_without_allocating() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        let bad = (MAX_WRAPPED_LEN as u32 + 1).to_be_bytes();
        encoded[offset::LENGTH..offset::PAYLOAD].copy_from_slice(&bad);
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::PayloadTooLong { .. })
        ));
    }

    /// Truncation and trailing bytes are rejected.
    #[test]
    fn exact_length_is_required() {
        let encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        for cut in [0_usize, 1, HEADER_LEN - 1, HEADER_LEN, encoded.len() - 1] {
            assert!(
                AuthBlob::parse(&encoded[..cut]).is_err(),
                "truncation to {cut} must be rejected"
            );
        }
        let mut longer = encoded.clone();
        longer.push(0);
        assert!(matches!(
            AuthBlob::parse(&longer),
            Err(Error::Malformed { .. })
        ));
    }

    /// A header that declares more bytes than the file holds is rejected.
    #[test]
    fn declared_length_beyond_the_file_is_rejected() {
        let mut encoded = AuthBlob::new(Backend::Mock, payload(32))
            .expect("valid")
            .encode();
        encoded[offset::LENGTH..offset::PAYLOAD].copy_from_slice(&33_u32.to_be_bytes());
        assert!(matches!(
            AuthBlob::parse(&encoded),
            Err(Error::Malformed { .. })
        ));
    }
}
