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

//! The Windows backend's private payload, inside the `Q2FABIO1` outer blob.
//!
//! # Format
//!
//! ```text
//!   version 1 (1)
//!   credential id length (2, BE)
//!   credential id (1 ..= 512)
//!   hmac-secret salt (32)
//!   XChaCha20-Poly1305 nonce (24)
//!   ciphertext of the 32-byte key and tag (48)
//! ```
//!
//! The credential id and the salt are inputs to the HMAC-secret derivation, so they
//! are bound to the key twice: the platform will not produce the same secret for a
//! different id or salt, and they also enter the AEAD's AAD. The version byte leaves
//! room to change the layout without changing the outer magic.

use crate::{Error, Result};

/// Payload format version.
pub(super) const VERSION: u8 = 1;

/// Maximum credential id length.
///
/// Windows Hello credential ids are tens of bytes; 512 keeps the whole payload
/// (`107 + id`) well inside the outer blob's 1024-byte limit.
pub(super) const MAX_CREDENTIAL_ID_LEN: usize = 512;

/// AAD prefix that binds the ciphertext to this backend and payload version.
pub(super) const AAD_PREFIX: &[u8] = b"qualia-bioauth windows webauthn v1";

/// HMAC-secret salt length.
pub(super) const SALT_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length.
pub(super) const NONCE_LEN: usize = 24;

/// Authentication tag length.
pub(super) const TAG_LEN: usize = 16;

/// Length of the wrapped master key.
const MASTER_KEY_LEN: usize = 32;

/// Ciphertext length: the key plus the tag.
pub(super) const CIPHERTEXT_LEN: usize = MASTER_KEY_LEN + TAG_LEN;

/// Fixed part of the payload: version, credential-id length, salt, nonce and ciphertext.
const FIXED_LEN: usize = 1 + 2 + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// Offsets of the fields that follow the credential id.
mod offset {
    /// Start of the version byte.
    pub const VERSION: usize = 0;
    /// Start of the credential-id length.
    pub const ID_LEN: usize = 1;
    /// Start of the credential id.
    pub const ID: usize = 3;
}

/// A parsed Windows payload.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Payload {
    /// Windows Hello credential id.
    credential_id: Vec<u8>,
    /// HMAC-secret salt.
    salt: [u8; SALT_LEN],
    /// AEAD nonce.
    nonce: [u8; NONCE_LEN],
    /// Ciphertext and tag.
    ciphertext: [u8; CIPHERTEXT_LEN],
}

impl core::fmt::Debug for Payload {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WindowsPayload")
            .field("credential_id_len", &self.credential_id.len())
            .finish_non_exhaustive()
    }
}

impl Payload {
    /// Builds a payload, validating the credential-id length.
    pub(super) fn new(
        credential_id: Vec<u8>,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
        ciphertext: [u8; CIPHERTEXT_LEN],
    ) -> Result<Self> {
        if credential_id.is_empty() {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows credential id is empty",
            });
        }
        if credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows credential id is longer than the format allows",
            });
        }
        Ok(Self {
            credential_id,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Parses a payload.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_LEN + 1 {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows payload is shorter than its fixed fields",
            });
        }
        if bytes[offset::VERSION] != VERSION {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows payload version is not supported",
            });
        }
        let id_len =
            u16::from_be_bytes([bytes[offset::ID_LEN], bytes[offset::ID_LEN + 1]]) as usize;
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows credential id length is outside the format limits",
            });
        }
        let expected = FIXED_LEN
            .checked_add(id_len)
            .ok_or(Error::WrappedPayloadInvalid {
                reason: "the Windows payload length overflows",
            })?;
        if bytes.len() != expected {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows payload length does not match its credential id length",
            });
        }

        let mut cursor = offset::ID;
        let credential_id = bytes[cursor..cursor + id_len].to_vec();
        cursor += id_len;
        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&bytes[cursor..cursor + SALT_LEN]);
        cursor += SALT_LEN;
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[cursor..cursor + NONCE_LEN]);
        cursor += NONCE_LEN;
        let mut ciphertext = [0_u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(&bytes[cursor..cursor + CIPHERTEXT_LEN]);

        Ok(Self {
            credential_id,
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Serializes the payload.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_LEN + self.credential_id.len());
        bytes.push(VERSION);
        bytes.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.credential_id);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Windows Hello credential id.
    pub(super) fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// HMAC-secret salt.
    pub(super) fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// AEAD nonce.
    pub(super) fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Ciphertext and tag.
    pub(super) fn ciphertext(&self) -> &[u8; CIPHERTEXT_LEN] {
        &self.ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload of a valid shape.
    fn sample(credential_id: &[u8]) -> Payload {
        Payload::new(
            credential_id.to_vec(),
            [0x11_u8; SALT_LEN],
            [0x22_u8; NONCE_LEN],
            [0x33_u8; CIPHERTEXT_LEN],
        )
        .expect("valid payload")
    }

    /// Encoding and parsing restore every field.
    #[test]
    fn roundtrip() {
        for length in [1_usize, 16, 64, MAX_CREDENTIAL_ID_LEN] {
            let payload = sample(&vec![0xAB_u8; length]);
            let encoded = payload.encode();
            assert_eq!(encoded.len(), FIXED_LEN + length);
            let parsed = Payload::parse(&encoded).expect("valid payload");
            assert_eq!(parsed, payload);
            assert_eq!(parsed.credential_id().len(), length);
            assert_eq!(parsed.salt(), &[0x11_u8; SALT_LEN]);
            assert_eq!(parsed.nonce(), &[0x22_u8; NONCE_LEN]);
        }
    }

    /// The fixed fields and the limits are a public contract.
    #[test]
    fn layout_is_stable() {
        assert_eq!(VERSION, 1);
        assert_eq!(MAX_CREDENTIAL_ID_LEN, 512);
        assert_eq!(SALT_LEN, 32);
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(CIPHERTEXT_LEN, 48);
        assert_eq!(FIXED_LEN, 107);
    }

    /// An empty credential id cannot be constructed.
    #[test]
    fn empty_credential_id_is_rejected() {
        assert!(matches!(
            Payload::new(
                Vec::new(),
                [0; SALT_LEN],
                [0; NONCE_LEN],
                [0; CIPHERTEXT_LEN]
            ),
            Err(Error::WrappedPayloadInvalid { .. })
        ));
    }

    /// An oversized credential id cannot be constructed.
    #[test]
    fn oversized_credential_id_is_rejected() {
        assert!(matches!(
            Payload::new(
                vec![0xAB; MAX_CREDENTIAL_ID_LEN + 1],
                [0; SALT_LEN],
                [0; NONCE_LEN],
                [0; CIPHERTEXT_LEN]
            ),
            Err(Error::WrappedPayloadInvalid { .. })
        ));
    }

    /// Changing a byte of every field is either rejected or changes the parsed value.
    #[test]
    fn tampering_does_not_silently_roundtrip() {
        let payload = sample(&[0xAB_u8; 32]);
        let encoded = payload.encode();
        for index in 0..encoded.len() {
            let mut tampered = encoded.clone();
            tampered[index] ^= 0x01;
            match Payload::parse(&tampered) {
                Err(_) => {}
                Ok(parsed) => assert_ne!(
                    parsed, payload,
                    "byte {index} was flipped but the payload parsed to the same value"
                ),
            }
        }
    }

    /// Truncation and trailing bytes are rejected.
    #[test]
    fn exact_length_is_required() {
        let encoded = sample(&[0xAB_u8; 32]).encode();
        for cut in [0_usize, 1, 3, 16, FIXED_LEN, encoded.len() - 1] {
            assert!(
                Payload::parse(&encoded[..cut]).is_err(),
                "truncation to {cut} must be rejected"
            );
        }
        let mut longer = encoded;
        longer.push(0);
        assert!(Payload::parse(&longer).is_err());
    }

    /// The version is checked before the variable-length fields.
    #[test]
    fn version_is_checked() {
        let mut encoded = sample(&[0xAB_u8; 32]).encode();
        encoded[offset::VERSION] = 2;
        assert!(matches!(
            Payload::parse(&encoded),
            Err(Error::WrappedPayloadInvalid { .. })
        ));
    }

    /// A credential id length of zero or above the limit is rejected.
    #[test]
    fn credential_id_length_is_bounded() {
        for length in [0_u16, (MAX_CREDENTIAL_ID_LEN + 1) as u16] {
            let mut encoded = sample(&[0xAB_u8; 32]).encode();
            encoded[offset::ID_LEN..offset::ID].copy_from_slice(&length.to_be_bytes());
            assert!(
                Payload::parse(&encoded).is_err(),
                "credential id length {length} must be rejected"
            );
        }
    }

    /// `Debug` does not print the credential id or the ciphertext.
    #[test]
    fn debug_is_redacted() {
        let payload = sample(&[0xAB_u8; 32]);
        let rendered = format!("{payload:?}");
        assert!(rendered.contains("credential_id_len"));
        assert!(!rendered.contains("ab"));
    }
}
