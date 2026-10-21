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

//! Windows backend: a Windows Hello credential whose `hmac-secret` output is the
//! wrapping key.
//!
//! # Why not CNG's `NCRYPT_UI_POLICY`
//!
//! A CNG key can be created with `NCRYPT_UI_PROTECT_KEY_FLAG`, and the Key Storage
//! Provider will refuse to finalize or use it without a "strong key" prompt. That
//! prompt is the CryptUI password/PIN protector, not Windows Hello, and the KSP caches
//! it for the process. Using it would ask the user to invent a second password and
//! would not use the Hello credential the user already has. This backend therefore
//! uses the Win32 WebAuthn API instead.
//!
//! # How the key is bound to Hello
//!
//! 1. `WebAuthNAuthenticatorMakeCredential` creates a platform credential with the
//!    PRF switch (`bEnablePrf`) and confirms that the platform reports it enabled.
//! 2. For every wrap and unwrap, `WebAuthNAuthenticatorGetAssertion` is called with
//!    `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG` and a 32-byte salt. The OS shows
//!    the Hello prompt, and only a successful gesture releases the 32-byte
//!    `hmac-secret`, which is the key that encrypts the master key.
//! 3. The credential id and the salt are stored in the payload, so the same Hello
//!    gesture reproduces the same secret after a restart. Both also enter the AEAD's
//!    AAD.
//!
//! The process never sees a key the platform would release without a gesture: if the
//! user cancels, the assertion fails and there is nothing to decrypt with. This is the
//! line the TODO draws between L3 and a `UserConsentVerifier` callback.
//!
//! # Availability
//!
//! `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable` reports a platform
//! **capability**, not whether this user has enrolled Hello. If it returns true and the
//! API version exposes the salt values, [`AuthBoundKeyStore::availability`] reports
//! [`Availability::Available`] and the first [`AuthBoundKeyStore::create`] makes the
//! real attempt. A `NotSupportedError` from that call is reported as
//! [`Error::Unavailable`] with a reason the user interface can show; it never falls
//! back to a software key.
//!
//! `hardware_backed` is reported as `false`: the Win32 WebAuthn API does not say
//! whether the platform authenticator is TPM-backed, and this crate does not guess.
//!
//! # Known limitation
//!
//! On Windows 11 23H2 (WebAuthn API version 7) the platform authenticator creates the
//! credential but reports the PRF extension as **not enabled** (`bPrfEnabled = 0`, no
//! extension output), even when the `hmac-secret` extension and `bEnablePrf` are both
//! requested. `create` therefore returns [`Error::Unavailable`], and the store remembers
//! that answer so later `availability` calls report it instead of offering the path
//! again. A Windows build whose platform authenticator enables PRF is required for this
//! backend to work; the password unlock path is unaffected.

mod payload;

use crate::format::AuthBlob;
use crate::key::{MASTER_KEY_LEN, MasterKey};
use crate::traits::{AuthBoundKeyStore, Availability, Backend};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::sync::{Mutex, PoisonError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_CLIENT_DATA, WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_CREDENTIALS, WEBAUTHN_EXTENSION, WEBAUTHN_EXTENSIONS,
    WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET, WEBAUTHN_HMAC_SECRET_SALT,
    WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential,
    WebAuthNDeletePlatformCredential, WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation,
    WebAuthNGetApiVersionNumber, WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use zeroize::Zeroize;

/// Relying-party identifier used for the credential.
///
/// A reserved `.invalid` domain: it never resolves, so a credential created for it
/// cannot be confused with a website's credential, and the WebAuthn API does not need
/// the origin to be reachable.
const RP_ID: &str = "qualia-bioauth.invalid";

/// Human-readable relying-party name shown by the platform.
const RP_NAME: &str = "Qualia2FA";

/// Origin written into the client data.
const ORIGIN: &str = "https://qualia-bioauth.invalid";

/// COSE identifier of ECDSA with SHA-256 (`-7`); windows-sys does not export it.
const COSE_ES256: i32 = -7;

/// Hash algorithm name the API expects alongside the client data.
const HASH_ALGORITHM: &str = "SHA-256";

/// How long the platform may wait for the Hello gesture.
const TIMEOUT_MS: u32 = 60_000;

/// The earliest WebAuthn API version that exposes the HMAC-secret salt values.
const MIN_API_VERSION: u32 = 7;

/// `NTE_USER_CANCELLED`: the user dismissed the Hello prompt.
const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;

/// `ERROR_CANCELLED`: some paths report a cancelled dialog as a Win32 error.
const ERROR_CANCELLED: i32 = 0x8007_04C7_u32 as i32;

/// `NTE_AUTHENTICATION_IGNORED`: the gesture did not verify the user.
const NTE_AUTHENTICATION_IGNORED: i32 = 0x8009_0031_u32 as i32;

/// `NTE_NOT_SUPPORTED`: the platform authenticator cannot perform this operation.
const NTE_NOT_SUPPORTED: i32 = 0x8009_0029_u32 as i32;

/// `NTE_INVALID_PARAMETER`: the platform rejected the request shape.
const NTE_INVALID_PARAMETER: i32 = 0x8009_0027_u32 as i32;

/// `NTE_DEVICE_NOT_READY`: no usable authenticator is enrolled.
const NTE_DEVICE_NOT_READY: i32 = 0x8009_0030_u32 as i32;

/// `NTE_NOT_FOUND`: the credential has already been deleted.
const NTE_NOT_FOUND: i32 = 0x8009_0011_u32 as i32;

/// A Windows auth-bound store backed by a Windows Hello credential.
///
/// The credential id is kept in memory after [`AuthBoundKeyStore::create`]. A store
/// that was just opened has no id yet, so [`AuthBoundKeyStore::wrap`] creates the
/// credential on its first call and [`AuthBoundKeyStore::delete`] can only remove a
/// credential created in this process. Use [`WindowsKeyStore::delete_blob`] to remove
/// the credential recorded in a persisted blob.
pub struct WindowsKeyStore {
    /// Credential id created in this process, if any.
    credential: Mutex<Option<Vec<u8>>>,
    /// A reason discovered by a failed attempt, reported by later `availability` calls.
    ///
    /// The WebAuthn capability check cannot see whether the platform authenticator
    /// actually enables PRF; only a creation attempt can. Remembering the answer keeps
    /// the user interface from offering a path that was just proved unusable.
    unavailable: Mutex<Option<&'static str>>,
    /// Serializes platform prompts: two Hello dialogs at once confuse the user and the
    /// authenticator.
    operation: Mutex<()>,
}

impl WindowsKeyStore {
    /// Creates an empty store.
    ///
    /// Nothing is created and no prompt is shown; [`AuthBoundKeyStore::availability`]
    /// reports what this machine supports.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credential: Mutex::new(None),
            unavailable: Mutex::new(None),
            operation: Mutex::new(()),
        }
    }

    /// Deletes the credential recorded in `blob`, without unwrapping it.
    ///
    /// This is what "turn biometric unlock off" needs after a restart: the store no
    /// longer remembers the credential id, but the blob still names it.
    ///
    /// # Errors
    ///
    /// - a malformed blob or one written by another backend: the usual format errors
    /// - a platform failure while deleting: [`Error::Platform`]
    pub fn delete_blob(&self, blob: &[u8]) -> Result<()> {
        let blob = AuthBlob::parse(blob)?;
        blob.expect_backend(Backend::WindowsWebAuthn)?;
        let payload = payload::Payload::parse(blob.wrapped())?;

        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        delete_credential(payload.credential_id())?;

        let mut current = self
            .credential
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if current.as_deref() == Some(payload.credential_id()) {
            *current = None;
        }
        Ok(())
    }

    /// Returns the current credential id, creating one if needed.
    fn ensure_credential(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.unavailable_reason() {
            return Err(Error::Unavailable { reason });
        }
        if let Some(credential) = self
            .credential
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(credential);
        }

        let credential = match make_credential(foreground_window()) {
            Ok(credential) => credential,
            Err(Error::Unavailable { reason }) => {
                self.remember_unavailable(reason);
                return Err(Error::Unavailable { reason });
            }
            Err(error) => return Err(error),
        };
        *self
            .credential
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(credential.clone());
        Ok(credential)
    }

    /// The reason a previous attempt found this backend unusable, if any.
    fn unavailable_reason(&self) -> Option<&'static str> {
        *self
            .unavailable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Remembers that this backend cannot work on this machine.
    fn remember_unavailable(&self, reason: &'static str) {
        *self
            .unavailable
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(reason);
    }

    /// A copy of the current credential id, if any.
    fn current_credential(&self) -> Option<Vec<u8>> {
        self.credential
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Default for WindowsKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for WindowsKeyStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WindowsKeyStore")
            .field("has_credential", &self.current_credential().is_some())
            .finish_non_exhaustive()
    }
}

impl AuthBoundKeyStore for WindowsKeyStore {
    fn availability(&self) -> Availability {
        if let Some(reason) = self.unavailable_reason() {
            return Availability::Unavailable { reason };
        }
        availability()
    }

    fn create(&self) -> Result<()> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.ensure_credential().map(|_| ())
    }

    fn wrap(&self, master: &MasterKey) -> Result<Vec<u8>> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let credential_id = self.ensure_credential()?;

        let mut salt = [0_u8; payload::SALT_LEN];
        random_bytes(&mut salt)?;
        let mut hmac_secret = get_hmac_secret(foreground_window(), &credential_id, &salt)?;

        let mut nonce = [0_u8; payload::NONCE_LEN];
        random_bytes(&mut nonce)?;
        let aad = associated_data(&credential_id, &salt);

        let cipher = XChaCha20Poly1305::new(&Key::from(hmac_secret));
        let encrypted = cipher.encrypt(
            &XNonce::from(nonce),
            AeadPayload {
                msg: master.expose_secret(),
                aad: &aad,
            },
        );
        hmac_secret.zeroize();
        let ciphertext = encrypted.map_err(|_| Error::Platform {
            operation: "encrypt the master key",
            code: 0,
        })?;
        if ciphertext.len() != payload::CIPHERTEXT_LEN {
            return Err(Error::WrappedPayloadInvalid {
                reason: "the Windows ciphertext does not have the fixed length",
            });
        }
        let mut fixed = [0_u8; payload::CIPHERTEXT_LEN];
        fixed.copy_from_slice(&ciphertext);

        let payload = payload::Payload::new(credential_id, salt, nonce, fixed)?;
        let blob = AuthBlob::new(Backend::WindowsWebAuthn, payload.encode())?;
        Ok(blob.encode())
    }

    fn unwrap(&self, blob: &[u8]) -> Result<MasterKey> {
        let blob = AuthBlob::parse(blob)?;
        blob.expect_backend(Backend::WindowsWebAuthn)?;
        let payload = payload::Payload::parse(blob.wrapped())?;
        if let Some(reason) = self.unavailable_reason() {
            return Err(Error::Unavailable { reason });
        }

        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut hmac_secret =
            get_hmac_secret(foreground_window(), payload.credential_id(), payload.salt())?;

        let aad = associated_data(payload.credential_id(), payload.salt());
        let cipher = XChaCha20Poly1305::new(&Key::from(hmac_secret));
        let decrypted = cipher.decrypt(
            &XNonce::from(*payload.nonce()),
            AeadPayload {
                msg: payload.ciphertext(),
                aad: &aad,
            },
        );
        hmac_secret.zeroize();
        let mut plaintext = decrypted.map_err(|_| Error::AuthenticationFailed)?;

        let master = MasterKey::from_bytes(&plaintext);
        plaintext.zeroize();
        master
    }

    fn delete(&self) -> Result<()> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.current_credential();
        if let Some(credential) = current {
            delete_credential(&credential)?;
            let mut stored = self
                .credential
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if stored.as_deref() == Some(credential.as_slice()) {
                *stored = None;
            }
        }
        Ok(())
    }
}

/// Reports what this machine supports.
fn availability() -> Availability {
    // SAFETY: no arguments and no preconditions.
    let version = unsafe { WebAuthNGetApiVersionNumber() };
    if version < MIN_API_VERSION {
        return Availability::Unavailable {
            reason: "this Windows version does not expose the WebAuthn hmac-secret extension",
        };
    }

    let mut available: i32 = 0;
    // SAFETY: the API writes one BOOL to the pointer.
    let status = unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&mut available) };
    if status < 0 || available == 0 {
        return Availability::Unavailable {
            reason: "this machine has no user-verifying platform authenticator",
        };
    }

    Availability::Available {
        backend: Backend::WindowsWebAuthn,
        hardware_backed: false,
    }
}

/// Returns the foreground window, or null when there is none.
fn foreground_window() -> HWND {
    // SAFETY: no arguments and no preconditions; null is a valid answer.
    unsafe { GetForegroundWindow() }
}

/// Fills `out` with random bytes from the system CSPRNG.
fn random_bytes(out: &mut [u8]) -> Result<()> {
    // SAFETY: `out` is a valid writable buffer of the length passed in; a null
    // algorithm handle with the system-preferred-RNG flag is the documented form.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            out.as_mut_ptr(),
            out.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        Err(Error::RandomnessUnavailable)
    } else {
        Ok(())
    }
}

/// The AAD that binds the credential id and the salt to the ciphertext.
fn associated_data(credential_id: &[u8], salt: &[u8; payload::SALT_LEN]) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(payload::AAD_PREFIX.len() + 2 + credential_id.len() + salt.len());
    aad.extend_from_slice(payload::AAD_PREFIX);
    aad.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(credential_id);
    aad.extend_from_slice(salt);
    aad
}

/// Creates a platform credential with the PRF/`hmac-secret` extension enabled.
fn make_credential(hwnd: HWND) -> Result<Vec<u8>> {
    let rp_id = wide(RP_ID);
    let rp_name = wide(RP_NAME);
    let user_name = wide("local");
    let user_display = wide("Qualia2FA");
    let hash_algorithm = wide(HASH_ALGORITHM);

    let relying_party = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: 1,
        pwszId: rp_id.as_ptr(),
        pwszName: rp_name.as_ptr(),
        pwszIcon: std::ptr::null(),
    };

    let mut user_id = [0_u8; 16];
    random_bytes(&mut user_id)?;
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: 1,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: user_name.as_ptr(),
        pwszIcon: std::ptr::null(),
        pwszDisplayName: user_display.as_ptr(),
    };

    let mut parameters = [WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: 1,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: COSE_ES256,
    }];
    let parameter_list = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: parameters.len() as u32,
        pCredentialParameters: parameters.as_mut_ptr(),
    };

    let mut challenge = [0_u8; 32];
    random_bytes(&mut challenge)?;
    let client_bytes = client_data("create", &challenge);
    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: 1,
        cbClientDataJSON: client_bytes.len() as u32,
        pbClientDataJSON: client_bytes.as_ptr().cast_mut(),
        pwszHashAlgId: hash_algorithm.as_ptr(),
    };

    let mut hmac_extension_value: i32 = 1;
    let mut hmac_extension = WEBAUTHN_EXTENSION {
        pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
        cbExtension: 4,
        pvExtension: (&mut hmac_extension_value as *mut i32).cast(),
    };
    let extensions = WEBAUTHN_EXTENSIONS {
        cExtensions: 1,
        pExtensions: &mut hmac_extension,
    };

    let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: 7,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        Extensions: extensions,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        bRequireResidentKey: 0,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        bEnablePrf: 1,
        ..Default::default()
    };

    let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
    // SAFETY: every pointer argument points at a live value for the duration of the
    // call; `attestation` is a valid out pointer. The API returns an owned object on
    // success, freed exactly once below.
    let status = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            hwnd,
            &relying_party,
            &user,
            &parameter_list,
            &client,
            &options,
            &mut attestation,
        )
    };
    if status < 0 {
        return Err(map_status("WebAuthNAuthenticatorMakeCredential", status));
    }
    if attestation.is_null() {
        return Err(Error::Platform {
            operation: "WebAuthNAuthenticatorMakeCredential returned no attestation",
            code: 0,
        });
    }

    let (credential_id, prf_enabled) = {
        // SAFETY: the API returned a valid, live attestation.
        let attestation = unsafe { &*attestation };
        let extension_says_enabled = hmac_extension_reported(&attestation.Extensions);
        if attestation.pbCredentialId.is_null() {
            (Vec::new(), false)
        } else {
            // SAFETY: the API reports a valid credential id and its length.
            let id = unsafe {
                std::slice::from_raw_parts(
                    attestation.pbCredentialId,
                    attestation.cbCredentialId as usize,
                )
            }
            .to_vec();
            (id, attestation.bPrfEnabled != 0 || extension_says_enabled)
        }
    };
    // SAFETY: the attestation is owned by this call and freed exactly once.
    unsafe { WebAuthNFreeCredentialAttestation(attestation) };

    if credential_id.is_empty() || credential_id.len() > payload::MAX_CREDENTIAL_ID_LEN {
        return Err(Error::WrappedPayloadInvalid {
            reason: "the platform returned an unusable credential id",
        });
    }
    if !prf_enabled {
        return Err(Error::Unavailable {
            reason: "the platform authenticator did not enable the PRF (hmac-secret) extension",
        });
    }
    Ok(credential_id)
}

/// Returns whether an attestation reports the `hmac-secret` extension as enabled.
///
/// The API has two ways of saying yes: the dedicated `bPrfEnabled` field and the
/// extension output list. Checking both keeps a platform that only fills one of them
/// from turning a supported credential into a false negative.
fn hmac_extension_reported(extensions: &WEBAUTHN_EXTENSIONS) -> bool {
    if extensions.cExtensions == 0 || extensions.pExtensions.is_null() {
        return false;
    }
    for index in 0..extensions.cExtensions as usize {
        // SAFETY: the API reported this many extension entries at a non-null pointer.
        let extension = unsafe { &*extensions.pExtensions.add(index) };
        if !wide_equals(extension.pwszExtensionIdentifier, "hmac-secret") {
            continue;
        }
        if extension.cbExtension != 4 || extension.pvExtension.is_null() {
            continue;
        }
        // SAFETY: the `hmac-secret` output type is a 4-byte BOOL.
        let enabled = unsafe { *(extension.pvExtension as *const i32) };
        if enabled != 0 {
            return true;
        }
    }
    false
}

/// Compares a NUL-terminated wide string to `text`.
fn wide_equals(pointer: windows_sys::core::PCWSTR, text: &str) -> bool {
    if pointer.is_null() {
        return false;
    }
    let mut index = 0_usize;
    for unit in text.encode_utf16() {
        // SAFETY: the caller passes a NUL-terminated string; the loop stops at the
        // first mismatch, so it never reads past a matching string's terminator.
        if unsafe { *pointer.add(index) } != unit {
            return false;
        }
        index += 1;
    }
    // SAFETY: reading the terminator of the string that matched every character above.
    unsafe { *pointer.add(index) == 0 }
}

/// Runs one assertion and returns the 32-byte `hmac-secret`.
fn get_hmac_secret(
    hwnd: HWND,
    credential_id: &[u8],
    salt: &[u8; payload::SALT_LEN],
) -> Result<[u8; 32]> {
    let hash_algorithm = wide(HASH_ALGORITHM);

    let mut challenge = [0_u8; 32];
    random_bytes(&mut challenge)?;
    let client_bytes = client_data("get", &challenge);
    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: 1,
        cbClientDataJSON: client_bytes.len() as u32,
        pbClientDataJSON: client_bytes.as_ptr().cast_mut(),
        pwszHashAlgId: hash_algorithm.as_ptr(),
    };

    let mut salt_bytes = *salt;
    let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: payload::SALT_LEN as u32,
        pbFirst: salt_bytes.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: std::ptr::null_mut(),
    };
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &mut hmac_salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };

    let mut credential_id_bytes = credential_id.to_vec();
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: 1,
        cbId: credential_id_bytes.len() as u32,
        pbId: credential_id_bytes.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };

    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: 7,
        dwTimeoutMilliseconds: TIMEOUT_MS,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut credential,
        },
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
        pHmacSecretSaltValues: &mut salt_values,
        ..Default::default()
    };

    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: every pointer argument points at a live value for the duration of the
    // call; `assertion` is a valid out pointer. The API returns an owned object on
    // success, freed exactly once below.
    let status = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            hwnd,
            wide(RP_ID).as_ptr(),
            &client,
            &options,
            &mut assertion,
        )
    };
    if status < 0 {
        return Err(map_status("WebAuthNAuthenticatorGetAssertion", status));
    }
    if assertion.is_null() {
        return Err(Error::Platform {
            operation: "WebAuthNAuthenticatorGetAssertion returned no assertion",
            code: 0,
        });
    }

    let secret = {
        // SAFETY: the API returned a valid, live assertion.
        let assertion = unsafe { &*assertion };
        let salt = assertion.pHmacSecret;
        if salt.is_null() {
            None
        } else {
            // SAFETY: the API returned a live HMAC-secret structure.
            let salt = unsafe { &*salt };
            if salt.cbFirst != MASTER_KEY_LEN as u32 || salt.pbFirst.is_null() {
                None
            } else {
                let mut out = [0_u8; MASTER_KEY_LEN];
                // SAFETY: the API reported 32 live bytes at a non-null pointer.
                unsafe {
                    std::ptr::copy_nonoverlapping(salt.pbFirst, out.as_mut_ptr(), MASTER_KEY_LEN)
                };
                Some(out)
            }
        }
    };
    // SAFETY: the assertion is owned by this call and freed exactly once. The secret
    // was copied out above.
    unsafe { WebAuthNFreeAssertion(assertion) };

    secret.ok_or(Error::WrappedPayloadInvalid {
        reason: "the platform did not return a 32-byte hmac-secret",
    })
}

/// Deletes one platform credential.
fn delete_credential(credential_id: &[u8]) -> Result<()> {
    // SAFETY: the pointer and length describe a live credential id.
    let status = unsafe {
        WebAuthNDeletePlatformCredential(credential_id.len() as u32, credential_id.as_ptr())
    };
    if status < 0 && status != NTE_NOT_FOUND {
        return Err(map_status("WebAuthNDeletePlatformCredential", status));
    }
    Ok(())
}

/// Maps a WebAuthn HRESULT to the crate's error.
fn map_status(operation: &'static str, status: i32) -> Error {
    match status {
        NTE_USER_CANCELLED | ERROR_CANCELLED | NTE_AUTHENTICATION_IGNORED => {
            Error::AuthenticationFailed
        }
        NTE_NOT_SUPPORTED | NTE_INVALID_PARAMETER | NTE_DEVICE_NOT_READY => Error::Unavailable {
            reason: "Windows Hello is not enrolled for this user, or the platform authenticator refused the request",
        },
        _ => Error::Platform {
            operation,
            code: status,
        },
    }
}

/// Encodes a string as NUL-terminated UTF-16.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Builds the WebAuthn client-data JSON.
fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        "{{\"type\":\"webauthn.{kind}\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\"}}",
        base64url(challenge)
    )
    .into_bytes()
}

/// Base64url without padding.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).copied().map_or(0, u32::from);
        let third = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (first << 16) | (second << 8) | third;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3F] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3F] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockKeyStore;

    /// Availability is a truthful answer, never a panic.
    #[test]
    fn availability_is_reported() {
        let availability = availability();
        if availability.is_available() {
            assert_eq!(availability.backend(), Some(Backend::WindowsWebAuthn));
        } else {
            match availability {
                Availability::Unavailable { reason } => assert!(!reason.is_empty()),
                other => panic!("unexpected availability: {other:?}"),
            }
        }
    }

    /// Deleting a store that holds nothing succeeds.
    #[test]
    fn delete_with_no_credential_is_ok() {
        let store = WindowsKeyStore::new();
        store.delete().expect("delete is idempotent");
    }

    /// A mock blob is rejected by the Windows backend before any platform call.
    #[test]
    fn mock_blob_is_rejected_as_the_wrong_backend() {
        let mock = MockKeyStore::new();
        let master = MasterKey::generate().expect("randomness");
        let blob = mock.wrap(&master).expect("wrap");

        let store = WindowsKeyStore::new();
        assert!(matches!(
            store.unwrap(&blob),
            Err(Error::WrongBackend {
                expected: Backend::WindowsWebAuthn,
                actual: Backend::Mock,
            })
        ));
        assert!(matches!(
            store.delete_blob(&blob),
            Err(Error::WrongBackend { .. })
        ));
    }

    /// The base64url encoder is unpadded and URL-safe.
    #[test]
    fn base64url_uses_the_url_safe_alphabet_without_padding() {
        assert_eq!(base64url(&[]), "");
        assert_eq!(base64url(&[0xFB_u8]), "-w");
        assert_eq!(base64url(&[0xFF_u8, 0xEF]), "_-8");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    /// The client-data JSON has the shape WebAuthn expects.
    #[test]
    fn client_data_has_the_expected_shape() {
        let json = String::from_utf8(client_data("get", &[0x11_u8; 4])).expect("utf-8");
        assert!(json.starts_with("{\"type\":\"webauthn.get\""));
        assert!(json.contains("\"challenge\":\"EREREQ\""));
        assert!(json.contains(ORIGIN));
    }

    /// A full round trip on a machine whose platform authenticator enables PRF.
    ///
    /// Ignored by default: it shows **three** Windows Hello prompts (create the
    /// credential, wrap, unwrap) and needs a real user to complete them. Run it
    /// deliberately on the acceptance machine:
    ///
    /// ```text
    /// cargo test --features mock -- --ignored --nocapture
    /// ```
    ///
    /// The output says which outcome happened:
    ///
    /// - `RESULT: roundtrip OK` — the platform released the `hmac-secret`, the wrapped
    ///   master key came back, and the credential was deleted;
    /// - `RESULT: PRF UNAVAILABLE: ...` — the platform created the credential but did
    ///   not enable the PRF extension. The test passes to show that the store fails
    ///   closed, but **this machine cannot run the Windows L3 path**.
    #[test]
    #[ignore = "requires an enrolled Windows Hello account and shows prompts"]
    fn hello_roundtrip() {
        // SAFETY: no arguments and no preconditions.
        let api_version = unsafe { WebAuthNGetApiVersionNumber() };
        let store = WindowsKeyStore::new();
        println!("WebAuthN API version: {api_version}");
        println!("availability: {:?}", store.availability());

        if !store.availability().is_available() {
            println!("RESULT: SKIPPED (no user-verifying platform authenticator)");
            return;
        }

        match store.create() {
            Ok(()) => println!("create: ok (Hello prompt completed)"),
            Err(Error::Unavailable { reason }) => {
                println!("RESULT: PRF UNAVAILABLE: {reason}");
                assert!(matches!(
                    store.availability(),
                    Availability::Unavailable { .. }
                ));
                return;
            }
            Err(error) => panic!("create failed: {error}"),
        }

        let master = MasterKey::generate().expect("randomness");
        let blob = store.wrap(&master).expect("wrap (Hello prompt)");
        println!("wrap: ok");
        let restored = store.unwrap(&blob).expect("unwrap (Hello prompt)");
        assert_eq!(restored, master);
        println!("unwrap: ok, the same master key came back");

        store.delete_blob(&blob).expect("delete the credential");
        assert!(
            store.unwrap(&blob).is_err(),
            "a deleted credential still unwraps"
        );
        println!("delete: ok, the old blob no longer unwraps");
        println!("RESULT: roundtrip OK");
    }
}
