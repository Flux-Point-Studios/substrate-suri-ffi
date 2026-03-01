//! C FFI for deriving sr25519 keypairs from Substrate SURI strings.
//!
//! Provides functions to:
//! - Derive a 32-byte public key (account ID) from a SURI
//! - Sign a message with sr25519 using the derived keypair
//! - Verify an sr25519 signature
//!
//! Build: `cargo build --release`
//! Output: `target/release/substrate_suri_ffi.dll` (Windows) or `.so` (Linux)

use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;

use sp_core::{crypto::Pair, sr25519};

/// Error codes returned by FFI functions.
const OK: i32 = 0;
const ERR_NULL_PTR: i32 = -1;
const ERR_INVALID_UTF8: i32 = -2;
const ERR_SURI_PARSE: i32 = -3;
const ERR_SIGN_FAILED: i32 = -4;
const ERR_VERIFY_FAILED: i32 = -5;

/// Derive a 32-byte sr25519 public key from a SURI string.
///
/// # Parameters
/// - `suri`: Null-terminated C string (e.g. "//Alice", "//Charlie", or a seed phrase)
/// - `out_public_32`: Pointer to 32-byte buffer for the public key
///
/// # Returns
/// 0 on success, negative error code on failure.
///
/// # Example SURI values
/// - `//Alice` — well-known dev account
/// - `//Charlie` — well-known dev account
/// - `bottom drive obey lake curtain smoke basket hold race lonely fit walk//Alice` — with derivation
#[no_mangle]
pub unsafe extern "C" fn substrate_suri_public_key(
    suri: *const c_char,
    out_public_32: *mut u8,
) -> i32 {
    if suri.is_null() || out_public_32.is_null() {
        return ERR_NULL_PTR;
    }

    let suri_str = match CStr::from_ptr(suri).to_str() {
        Ok(s) => s,
        Err(_) => return ERR_INVALID_UTF8,
    };

    let pair = match sr25519::Pair::from_string(suri_str, None) {
        Ok(p) => p,
        Err(_) => return ERR_SURI_PARSE,
    };

    let public = pair.public();
    let out_slice = slice::from_raw_parts_mut(out_public_32, 32);
    out_slice.copy_from_slice(public.as_ref());

    OK
}

/// Derive a 64-byte sr25519 keypair (32-byte secret + 32-byte nonce) from a SURI string.
///
/// # Parameters
/// - `suri`: Null-terminated C string
/// - `out_secret_64`: Pointer to 64-byte buffer for the raw keypair bytes
///   (first 32 bytes = mini-secret, next 32 bytes = nonce)
/// - `out_public_32`: Pointer to 32-byte buffer for the public key
///
/// # Returns
/// 0 on success, negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn substrate_suri_keypair(
    suri: *const c_char,
    out_secret_64: *mut u8,
    out_public_32: *mut u8,
) -> i32 {
    if suri.is_null() || out_secret_64.is_null() || out_public_32.is_null() {
        return ERR_NULL_PTR;
    }

    let suri_str = match CStr::from_ptr(suri).to_str() {
        Ok(s) => s,
        Err(_) => return ERR_INVALID_UTF8,
    };

    let pair = match sr25519::Pair::from_string(suri_str, None) {
        Ok(p) => p,
        Err(_) => return ERR_SURI_PARSE,
    };

    // sp_core::sr25519::Pair exposes to_raw_vec() which gives the 64-byte secret
    let raw = pair.to_raw_vec();
    let secret_slice = slice::from_raw_parts_mut(out_secret_64, 64);
    secret_slice.copy_from_slice(&raw[..64]);

    let public = pair.public();
    let pub_slice = slice::from_raw_parts_mut(out_public_32, 32);
    pub_slice.copy_from_slice(public.as_ref());

    OK
}

/// Sign a message using sr25519 derived from a SURI string.
///
/// # Parameters
/// - `suri`: Null-terminated C string
/// - `msg`: Pointer to message bytes
/// - `msg_len`: Length of message in bytes
/// - `out_sig_64`: Pointer to 64-byte buffer for the sr25519 signature
///
/// # Returns
/// 0 on success, negative error code on failure.
#[no_mangle]
pub unsafe extern "C" fn substrate_suri_sign(
    suri: *const c_char,
    msg: *const u8,
    msg_len: u32,
    out_sig_64: *mut u8,
) -> i32 {
    if suri.is_null() || msg.is_null() || out_sig_64.is_null() {
        return ERR_NULL_PTR;
    }

    let suri_str = match CStr::from_ptr(suri).to_str() {
        Ok(s) => s,
        Err(_) => return ERR_INVALID_UTF8,
    };

    let pair = match sr25519::Pair::from_string(suri_str, None) {
        Ok(p) => p,
        Err(_) => return ERR_SURI_PARSE,
    };

    let message = slice::from_raw_parts(msg, msg_len as usize);
    let signature = pair.sign(message);

    let sig_bytes: &[u8] = signature.as_ref();
    if sig_bytes.len() != 64 {
        return ERR_SIGN_FAILED;
    }

    let out_slice = slice::from_raw_parts_mut(out_sig_64, 64);
    out_slice.copy_from_slice(sig_bytes);

    OK
}

/// Verify an sr25519 signature against a public key and message.
///
/// # Parameters
/// - `public_32`: Pointer to 32-byte public key
/// - `msg`: Pointer to message bytes
/// - `msg_len`: Length of message in bytes
/// - `sig_64`: Pointer to 64-byte signature
///
/// # Returns
/// 0 if signature is valid, -5 if invalid, negative error code on other failure.
#[no_mangle]
pub unsafe extern "C" fn substrate_suri_verify(
    public_32: *const u8,
    msg: *const u8,
    msg_len: u32,
    sig_64: *const u8,
) -> i32 {
    if public_32.is_null() || msg.is_null() || sig_64.is_null() {
        return ERR_NULL_PTR;
    }

    let pub_slice = slice::from_raw_parts(public_32, 32);
    let public = match sr25519::Public::try_from(pub_slice) {
        Ok(p) => p,
        Err(_) => return ERR_NULL_PTR,
    };

    let sig_slice = slice::from_raw_parts(sig_64, 64);
    let signature = match sr25519::Signature::try_from(sig_slice) {
        Ok(s) => s,
        Err(_) => return ERR_SIGN_FAILED,
    };

    let message = slice::from_raw_parts(msg, msg_len as usize);

    if sr25519::Pair::verify(&signature, message, &public) {
        OK
    } else {
        ERR_VERIFY_FAILED
    }
}

/// Get the last error message as a null-terminated string.
/// Currently returns a static string based on error code.
///
/// # Parameters
/// - `error_code`: The error code returned by a previous FFI call
/// - `out_buf`: Pointer to buffer for error message
/// - `buf_len`: Length of buffer
///
/// # Returns
/// Number of bytes written (excluding null terminator), or -1 if buffer too small.
#[no_mangle]
pub unsafe extern "C" fn substrate_suri_error_message(
    error_code: i32,
    out_buf: *mut c_char,
    buf_len: u32,
) -> i32 {
    if out_buf.is_null() {
        return ERR_NULL_PTR;
    }

    let msg = match error_code {
        0 => "success",
        -1 => "null pointer argument",
        -2 => "invalid UTF-8 in SURI string",
        -3 => "failed to parse SURI (bad format or unknown derivation)",
        -4 => "signing failed",
        -5 => "signature verification failed",
        _ => "unknown error",
    };

    let msg_bytes = msg.as_bytes();
    let copy_len = msg_bytes.len().min((buf_len as usize).saturating_sub(1));
    if copy_len == 0 && buf_len > 0 {
        *out_buf = 0;
        return 0;
    }

    let out_slice = slice::from_raw_parts_mut(out_buf as *mut u8, copy_len + 1);
    out_slice[..copy_len].copy_from_slice(&msg_bytes[..copy_len]);
    out_slice[copy_len] = 0; // null terminator

    copy_len as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_alice_public_key() {
        let suri = CString::new("//Alice").unwrap();
        let mut public = [0u8; 32];
        let result = unsafe { substrate_suri_public_key(suri.as_ptr(), public.as_mut_ptr()) };
        assert_eq!(result, OK);
        assert_ne!(public, [0u8; 32]); // should be non-zero
    }

    #[test]
    fn test_charlie_public_key() {
        let suri = CString::new("//Charlie").unwrap();
        let mut public = [0u8; 32];
        let result = unsafe { substrate_suri_public_key(suri.as_ptr(), public.as_mut_ptr()) };
        assert_eq!(result, OK);
        assert_ne!(public, [0u8; 32]);
    }

    #[test]
    fn test_keypair() {
        let suri = CString::new("//Alice").unwrap();
        let mut secret = [0u8; 64];
        let mut public = [0u8; 32];
        let result = unsafe {
            substrate_suri_keypair(suri.as_ptr(), secret.as_mut_ptr(), public.as_mut_ptr())
        };
        assert_eq!(result, OK);
        assert_ne!(secret, [0u8; 64]);
        assert_ne!(public, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify() {
        let suri = CString::new("//Alice").unwrap();
        let msg = b"hello materios";
        let mut sig = [0u8; 64];
        let mut public = [0u8; 32];

        // Get public key
        let result = unsafe { substrate_suri_public_key(suri.as_ptr(), public.as_mut_ptr()) };
        assert_eq!(result, OK);

        // Sign
        let result = unsafe {
            substrate_suri_sign(
                suri.as_ptr(),
                msg.as_ptr(),
                msg.len() as u32,
                sig.as_mut_ptr(),
            )
        };
        assert_eq!(result, OK);

        // Verify
        let result = unsafe {
            substrate_suri_verify(
                public.as_ptr(),
                msg.as_ptr(),
                msg.len() as u32,
                sig.as_ptr(),
            )
        };
        assert_eq!(result, OK);
    }

    #[test]
    fn test_bad_suri() {
        let suri = CString::new("not a valid suri !!!").unwrap();
        let mut public = [0u8; 32];
        let result = unsafe { substrate_suri_public_key(suri.as_ptr(), public.as_mut_ptr()) };
        assert_eq!(result, ERR_SURI_PARSE);
    }

    #[test]
    fn test_invalid_signature() {
        let suri = CString::new("//Alice").unwrap();
        let msg = b"hello";
        let fake_sig = [0u8; 64]; // all zeros = invalid signature
        let mut public = [0u8; 32];

        let result = unsafe { substrate_suri_public_key(suri.as_ptr(), public.as_mut_ptr()) };
        assert_eq!(result, OK);

        let result = unsafe {
            substrate_suri_verify(
                public.as_ptr(),
                msg.as_ptr(),
                msg.len() as u32,
                fake_sig.as_ptr(),
            )
        };
        assert_eq!(result, ERR_VERIFY_FAILED);
    }
}
