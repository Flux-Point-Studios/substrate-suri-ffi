# Substrate Integration Guide for Game Engines

How to submit extrinsics to a Substrate chain from Unreal Engine, Unity, or any C/C++ game client using raw SCALE encoding and sr25519 signing.

## Architecture Overview

```
Game Client                          Substrate Chain
───────────                          ───────────────
1. SCALE-encode call data            Pallet receives extrinsic
2. Wrap in signed extrinsic          Runtime validates signature
3. sr25519 sign (via this FFI)       Dispatch to pallet function
4. Submit via JSON-RPC               State updated on-chain
```

## Prerequisites

- **substrate_suri_ffi** library (this repo) for sr25519 key operations
- **SHA-256** implementation (libsodium, OpenSSL, or engine-native)
- **WebSocket or HTTP** client for JSON-RPC
- **SCALE codec** encoder (you must implement this — see below)

## SCALE Encoding Primer

Substrate uses SCALE (Simple Concatenated Aggregate Little-Endian) encoding. The critical types for game integration:

### Fixed-Size Types

| Type | Encoding | Size |
|------|----------|------|
| `u8` | Raw byte | 1 byte |
| `u32` | Little-endian | 4 bytes |
| `u64` | Little-endian | 8 bytes |
| `H256` | 32 raw bytes | 32 bytes |
| `[u8; 32]` | 32 raw bytes | 32 bytes |
| `bool` | `0x00` false, `0x01` true | 1 byte |

### Variable-Size Types

| Type | Encoding | Size |
|------|----------|------|
| `Option<T>` | `0x00` = None, `0x01` + T = Some | 1 or 1+sizeof(T) |
| `Vec<u8>` | Compact length prefix + bytes | Variable |
| `Compact<u32>` | 1-5 bytes (see below) | Variable |

### Compact Integer Encoding

```
Value 0-63:        1 byte   (value << 2) | 0b00
Value 64-16383:    2 bytes  (value << 2) | 0b01, little-endian
Value 16384-2^30:  4 bytes  (value << 2) | 0b10, little-endian
Value >2^30:       5+ bytes 0b11 prefix + raw bytes
```

### Option Encoding (Common Mistake)

```
Option<[u8; 32]> = None:  0x00                          (1 byte)
Option<[u8; 32]> = Some:  0x01 + 32 bytes of data       (33 bytes)
```

**Do NOT send 32 zero bytes for None** — the decoder reads `0x00` as None (1 byte), then the remaining 31 zero bytes corrupt every subsequent field.

## Extrinsic Structure

A signed Substrate extrinsic has this layout:

```
┌─────────────────────────────────────────────┐
│ Compact<u32> length (of everything below)   │
├─────────────────────────────────────────────┤
│ 0x84 (signed extrinsic, version 4)          │
│ 0x00 (address type: AccountId32)            │
│ [u8; 32] signer public key                  │
│ 0x01 (signature type: sr25519)              │
│ [u8; 64] sr25519 signature                  │
│ Era (0x00 = immortal)                       │
│ Compact<u32> nonce                          │
│ Compact<u128> tip (0x00 = no tip)           │
├─────────────────────────────────────────────┤
│ u8 pallet_index                             │
│ u8 call_index                               │
│ ... call arguments (SCALE-encoded) ...      │
└─────────────────────────────────────────────┘
```

### Signing Payload

The signature covers:

```
sign_payload = call_data || extra || additional

call_data   = pallet_index || call_index || args...
extra       = era || nonce || tip
additional  = spec_version(u32 LE) || tx_version(u32 LE) || genesis_hash(32) || block_hash(32)
```

If `sign_payload` exceeds 256 bytes, sign `SHA-256(sign_payload)` instead.

### Getting Chain Metadata via RPC

```json
// Get runtime version (for spec_version, tx_version)
{"jsonrpc":"2.0","id":1,"method":"state_getRuntimeVersion","params":[]}

// Get genesis hash
{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[0]}

// Get current best block hash (for mortal era, or use genesis for immortal)
{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[]}

// Get account nonce
{"jsonrpc":"2.0","id":1,"method":"system_accountNextIndex","params":["5FLSigC9..."]}

// Submit signed extrinsic
{"jsonrpc":"2.0","id":1,"method":"author_submitExtrinsic","params":["0x..."]}
```

## Nonce Management

Each account has an incrementing nonce. Sending two extrinsics with the same nonce causes "Priority is too low" errors.

**Strategies:**
- **Sequential**: Wait for each tx to be included before sending the next
- **Pre-increment**: Query `system_accountNextIndex`, use it, increment locally for the next tx
- **Batch**: If the pallet supports `utility.batch`, bundle multiple calls in one extrinsic

## Transaction Fees

Most Substrate chains charge fees per extrinsic. Check with the chain operator for:
- Which token pays fees (some chains use a separate fee token)
- Fee amount per extrinsic type
- How to fund your account

## Example: Submitting an Extrinsic from C++

```cpp
#include "substrate_suri_ffi.h"
#include <vector>

// 1. Build call data
std::vector<uint8_t> call;
call.push_back(PALLET_INDEX);   // e.g. 7
call.push_back(CALL_INDEX);     // e.g. 0
// ... append SCALE-encoded arguments ...

// 2. Get signer public key
uint8_t PublicKey[32];
substrate_suri_public_key("//Charlie", PublicKey);

// 3. Build signing payload
std::vector<uint8_t> payload;
payload.insert(payload.end(), call.begin(), call.end());
// append: era(1) + nonce(compact) + tip(1)
// append: spec_version(4) + tx_version(4) + genesis_hash(32) + block_hash(32)

// 4. Sign (hash first if >256 bytes)
uint8_t Signature[64];
if (payload.size() > 256) {
    uint8_t hash[32];
    sha256(payload.data(), payload.size(), hash);
    substrate_suri_sign("//Charlie", hash, 32, Signature);
} else {
    substrate_suri_sign("//Charlie", payload.data(), payload.size(), Signature);
}

// 5. Assemble signed extrinsic
std::vector<uint8_t> extrinsic;
extrinsic.push_back(0x84);                                   // signed, version 4
extrinsic.push_back(0x00);                                   // address type
extrinsic.insert(extrinsic.end(), PublicKey, PublicKey + 32); // signer
extrinsic.push_back(0x01);                                   // sr25519
extrinsic.insert(extrinsic.end(), Signature, Signature + 64);// signature
extrinsic.push_back(0x00);                                   // immortal era
append_compact(extrinsic, nonce);                             // nonce
extrinsic.push_back(0x00);                                   // tip = 0
extrinsic.insert(extrinsic.end(), call.begin(), call.end());  // call data

// 6. Prepend length
std::vector<uint8_t> final_tx;
append_compact(final_tx, extrinsic.size());
final_tx.insert(final_tx.end(), extrinsic.begin(), extrinsic.end());

// 7. Submit via JSON-RPC
// POST {"jsonrpc":"2.0","id":1,"method":"author_submitExtrinsic","params":["0x<hex>"]}
```

## Materios Testnet Example

For the [Materios](https://github.com/Flux-Point-Studios/materios) partner chain, the full pipeline includes a blob gateway for data availability:

```
┌─────────────┐    HTTP     ┌──────────────┐
│ Game Client ├────────────►│ Blob Gateway │  ← upload data chunks
└──────┬──────┘             └──────────────┘
       │ WS/HTTP
       ▼
┌──────────────┐            ┌──────────────┐
│ Materios RPC ├───────────►│ Cert Daemon  │  ← auto-certifies (~10s)
└──────────────┘            └──────┬───────┘
                                   │
                            ┌──────▼───────┐
                            │  Checkpoint  │  ← auto-anchors (~2.5 min)
                            └──────────────┘
```

**Testnet credentials** (request current values from the Materios team):

| Item | Description |
|------|-------------|
| RPC endpoint | WebSocket or HTTP URL to the chain's RPC node |
| Blob gateway URL | HTTP endpoint for uploading data chunks |
| Gateway API key | Authentication for blob uploads |
| Account SURI | Dev account like `//Charlie` or a funded mnemonic |
| Genesis hash | Via `chain_getBlockHash(0)` — needed for signing |
| SS58 prefix | Chain-specific address encoding prefix |

**Pallet call — `orinqReceipts.submitReceipt` (pallet 7, call 0):**

```
0x07 0x00                               // pallet 7, call 0
receipt_id:              H256            // SHA-256(contentHash bytes)
content_hash:            H256            // SHA-256 of raw content
base_root_sha256:        [u8;32]         // Merkle root (= content_hash for single items)
zk_root_poseidon:        Option<[u8;32]> // 0x00 (None)
poseidon_params_hash:    Option<[u8;32]> // 0x00 (None)
base_manifest_hash:      [u8;32]         // manifest hash
safety_manifest_hash:    [u8;32]         // 32 zero bytes (unused)
monitor_config_hash:     [u8;32]         // 32 zero bytes (unused)
attestation_evidence_hash: [u8;32]       // 32 zero bytes (unused)
storage_locator_hash:    [u8;32]         // 32 zero bytes (unused)
schema_hash:             [u8;32]         // 32 zero bytes (unused)
```

Total call data: 324 bytes.

**Blob upload (required before certification):**

```
POST /blobs/{contentHash}/manifest     + x-api-key header + JSON body
PUT  /blobs/{contentHash}/chunks/{i}   + x-api-key header + binary body
```

Without blob upload, the cert daemon cannot verify data and certification never completes.

**Polling for certification:**

Query `orinqReceipts.receipts(receiptId)` via `state_getStorage`. When `availability_cert_hash` is non-zero, the receipt is certified.

**Checkpoint leaf hash (for verification):**

```
leaf = SHA-256("materios-checkpoint-v1" || genesis_hash[32] || receipt_id[32] || cert_hash[32])
```

## Common Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Option encoded as raw bytes | Every field after the Option is garbled | Use `0x00` for None (1 byte), not 32 zero bytes |
| Wrong field order in call | Extrinsic fails with decode error | Match exact order from pallet Rust source |
| Signing raw payload >256 bytes | Invalid signature | Hash the payload with SHA-256 first, then sign the hash |
| Reusing nonce | "Priority is too low" | Query `system_accountNextIndex` before each tx |
| Immortal era with wrong block hash | Invalid signature | Use genesis hash as block_hash for immortal era |
| Compact encoding wrong | Length prefix corrupted | Test compact encoder against known values (0→0x00, 64→0x01_01, etc.) |
