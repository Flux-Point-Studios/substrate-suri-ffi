/**
 * substrate_suri_ffi — C FFI for Substrate sr25519 key derivation and signing.
 *
 * Derives sr25519 keypairs from SURI strings (e.g. "//Alice", "//Charlie",
 * seed phrases with derivation paths) and provides signing/verification.
 *
 * Link against: substrate_suri_ffi.dll (Windows) or libsubstrate_suri_ffi.so (Linux)
 */

#ifndef SUBSTRATE_SURI_FFI_H
#define SUBSTRATE_SURI_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define SURI_OK              0
#define SURI_ERR_NULL_PTR   -1
#define SURI_ERR_INVALID_UTF8 -2
#define SURI_ERR_SURI_PARSE -3
#define SURI_ERR_SIGN       -4
#define SURI_ERR_VERIFY     -5

/**
 * Derive a 32-byte sr25519 public key from a SURI string.
 *
 * @param suri           Null-terminated SURI (e.g. "//Charlie")
 * @param out_public_32  Output buffer, must be at least 32 bytes
 * @return SURI_OK on success, negative error code on failure
 */
int32_t substrate_suri_public_key(const char* suri, uint8_t* out_public_32);

/**
 * Derive a full sr25519 keypair from a SURI string.
 *
 * @param suri           Null-terminated SURI
 * @param out_secret_64  Output buffer for secret key (64 bytes: 32 mini-secret + 32 nonce)
 * @param out_public_32  Output buffer for public key (32 bytes)
 * @return SURI_OK on success, negative error code on failure
 */
int32_t substrate_suri_keypair(const char* suri, uint8_t* out_secret_64, uint8_t* out_public_32);

/**
 * Sign a message using sr25519 derived from a SURI string.
 *
 * @param suri        Null-terminated SURI
 * @param msg         Pointer to message bytes
 * @param msg_len     Length of message
 * @param out_sig_64  Output buffer for signature (64 bytes)
 * @return SURI_OK on success, negative error code on failure
 */
int32_t substrate_suri_sign(const char* suri, const uint8_t* msg, uint32_t msg_len, uint8_t* out_sig_64);

/**
 * Verify an sr25519 signature.
 *
 * @param public_32  Public key (32 bytes)
 * @param msg        Pointer to message bytes
 * @param msg_len    Length of message
 * @param sig_64     Signature to verify (64 bytes)
 * @return SURI_OK if valid, SURI_ERR_VERIFY if invalid
 */
int32_t substrate_suri_verify(const uint8_t* public_32, const uint8_t* msg, uint32_t msg_len, const uint8_t* sig_64);

/**
 * Get a human-readable error message for an error code.
 *
 * @param error_code  Error code from a previous call
 * @param out_buf     Output buffer for null-terminated string
 * @param buf_len     Buffer size
 * @return Number of bytes written (excluding null terminator)
 */
int32_t substrate_suri_error_message(int32_t error_code, char* out_buf, uint32_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* SUBSTRATE_SURI_FFI_H */
