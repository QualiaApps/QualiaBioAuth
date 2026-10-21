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

//! Diagnostic binary for the Windows Hello acceptance run.
//!
//! It creates a WebAuthn credential, wraps a random 32-byte key with the platform's
//! `hmac-secret`, unwraps it, and deletes the credential. It never reads a Qualia2FA
//! vault and never touches user data.
//!
//! Run it from an interactive desktop session with Windows Hello already enrolled:
//!
//! ```text
//! cargo run --features mock --bin hello_probe
//! ```
//!
//! The last line starts with `RESULT:` and one of `roundtrip OK`, `PRF UNAVAILABLE`,
//! `SKIPPED` or `FAILED`.

#[cfg(target_os = "windows")]
fn main() {
    use qualia_bioauth::platform::windows::{WindowsKeyStore, api_version};
    use qualia_bioauth::{AuthBoundKeyStore, MasterKey};

    println!("QualiaBioAuth Windows Hello acceptance run");
    println!("WebAuthn API version: {}", api_version());

    let store = WindowsKeyStore::new();
    let availability = store.availability();
    println!("availability: {availability:?}");
    if !availability.is_available() {
        println!("RESULT: SKIPPED (no user-verifying platform authenticator)");
        return;
    }

    println!("You will see three Windows Hello prompts: create, wrap, unwrap.");
    match store.create() {
        Ok(()) => println!("create: ok"),
        Err(qualia_bioauth::Error::Unavailable { reason }) => {
            println!("RESULT: PRF UNAVAILABLE: {reason}");
            return;
        }
        Err(error) => {
            println!("RESULT: FAILED at create: {error}");
            std::process::exit(1);
        }
    }

    let master = match MasterKey::generate() {
        Ok(master) => master,
        Err(error) => {
            println!("RESULT: FAILED generating a test key: {error}");
            std::process::exit(1);
        }
    };

    let blob = match store.wrap(&master) {
        Ok(blob) => {
            println!("wrap: ok");
            blob
        }
        Err(qualia_bioauth::Error::Unavailable { reason }) => {
            let _ = store.delete();
            println!("RESULT: PRF UNAVAILABLE: {reason}");
            return;
        }
        Err(error) => {
            let _ = store.delete();
            println!("RESULT: FAILED at wrap: {error}");
            std::process::exit(1);
        }
    };

    match store.unwrap(&blob) {
        Ok(restored) if restored == master => println!("unwrap: ok, the same key came back"),
        Ok(_) => {
            let _ = store.delete();
            println!("RESULT: FAILED: the unwrapped key differs from the original");
            std::process::exit(1);
        }
        Err(qualia_bioauth::Error::Unavailable { reason }) => {
            let _ = store.delete();
            println!("RESULT: PRF UNAVAILABLE: {reason}");
            return;
        }
        Err(error) => {
            let _ = store.delete();
            println!("RESULT: FAILED at unwrap: {error}");
            std::process::exit(1);
        }
    }

    match store.delete_blob(&blob) {
        Ok(()) => println!("delete: ok"),
        Err(error) => {
            println!("RESULT: FAILED at delete: {error}");
            std::process::exit(1);
        }
    }

    if store.unwrap(&blob).is_ok() {
        println!("RESULT: FAILED: a deleted credential still unwraps");
        std::process::exit(1);
    }
    println!("RESULT: roundtrip OK");
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("This diagnostic exercises the Windows backend and only runs on Windows.");
    println!("RESULT: SKIPPED (not Windows)");
}
