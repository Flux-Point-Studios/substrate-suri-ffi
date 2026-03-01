# substrate-suri-ffi

C FFI library for deriving **sr25519** keypairs from Substrate SURI strings. Drop the prebuilt `.dll`/`.so` into your Unreal Engine, Unity, or any C/C++ project to sign Substrate extrinsics without embedding a Rust toolchain.

## Prebuilt Binaries

```
dist/
  substrate_suri_ffi.h              # C header
  win64/
    substrate_suri_ffi.dll          # Windows x86_64 (1.7 MB)
    substrate_suri_ffi.lib          # Static lib for MSVC linking
  linux-x86_64/
    libsubstrate_suri_ffi.so        # Linux x86_64 (749 KB)
    libsubstrate_suri_ffi.a         # Static lib
```

## API

```c
#include "substrate_suri_ffi.h"

// Derive 32-byte public key from SURI
int32_t substrate_suri_public_key(const char* suri, uint8_t* out_public_32);

// Derive full keypair (64-byte secret + 32-byte public)
int32_t substrate_suri_keypair(const char* suri, uint8_t* out_secret_64, uint8_t* out_public_32);

// Sign a message with sr25519
int32_t substrate_suri_sign(const char* suri, const uint8_t* msg, uint32_t msg_len, uint8_t* out_sig_64);

// Verify an sr25519 signature
int32_t substrate_suri_verify(const uint8_t* public_32, const uint8_t* msg, uint32_t msg_len, const uint8_t* sig_64);

// Human-readable error message
int32_t substrate_suri_error_message(int32_t error_code, char* out_buf, uint32_t buf_len);
```

All functions return `0` on success, negative error code on failure.

## SURI Examples

| SURI | Description |
|------|-------------|
| `//Alice` | Well-known dev account |
| `//Charlie` | Well-known dev account |
| `bottom drive obey lake curtain smoke basket hold race lonely fit walk` | 12-word mnemonic |
| `<mnemonic>//hard/soft` | Mnemonic with derivation path |

## Unreal Engine Integration

1. Copy `substrate_suri_ffi.dll` to `YourPlugin/ThirdParty/SubstrateSuri/bin/Win64/`
2. Copy `substrate_suri_ffi.h` to `YourPlugin/ThirdParty/SubstrateSuri/include/`
3. In your `.Build.cs`:
   ```csharp
   string ThirdPartyPath = Path.Combine(ModuleDirectory, "..", "ThirdParty", "SubstrateSuri");
   PublicIncludePaths.Add(Path.Combine(ThirdPartyPath, "include"));
   PublicAdditionalLibraries.Add(Path.Combine(ThirdPartyPath, "bin", "Win64", "substrate_suri_ffi.lib"));
   RuntimeDependencies.Add("$(BinaryOutputDir)/substrate_suri_ffi.dll",
       Path.Combine(ThirdPartyPath, "bin", "Win64", "substrate_suri_ffi.dll"));
   ```
4. Call from C++:
   ```cpp
   #include "substrate_suri_ffi.h"

   uint8_t PublicKey[32];
   int32_t Result = substrate_suri_public_key("//Charlie", PublicKey);
   if (Result != 0) { /* handle error */ }
   ```

## Building from Source

```bash
# Linux
cargo build --release
# Output: target/release/libsubstrate_suri_ffi.so

# Windows (cross-compile from Linux)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# Output: target/x86_64-pc-windows-gnu/release/substrate_suri_ffi.dll

# Windows (native MSVC)
cargo build --release --target x86_64-pc-windows-msvc
# Output: target/x86_64-pc-windows-msvc/release/substrate_suri_ffi.dll

# Android
rustup target add aarch64-linux-android
cargo build --release --target aarch64-linux-android
# Output: target/aarch64-linux-android/release/libsubstrate_suri_ffi.so
```

Requires Rust 1.70+ and `sp-core` v34.

## Tests

```bash
cargo test
```

6 tests: key derivation (Alice, Charlie), keypair extraction, sign+verify round-trip, bad SURI rejection, invalid signature detection.

## License

MIT
