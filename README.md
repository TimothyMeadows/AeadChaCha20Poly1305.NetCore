# AeadChaCha20Poly1305.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![nuget](https://img.shields.io/nuget/v/AeadChaCha20Poly1305.NetCore.svg)](https://www.nuget.org/packages/AeadChaCha20Poly1305.NetCore/)

`AeadChaCha20Poly1305.NetCore` is a .NET implementation of **AEAD_CHACHA20_POLY1305** (RFC 8439).

It provides authenticated encryption with associated data (AEAD) using:

- **ChaCha20** for encryption/decryption
- **Poly1305** for authentication tags

The API is optimized for integration with [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) and supports both `PinnedMemory<byte>` and `byte[]` output workflows.

You can read more in:

- RFC 8439 (ChaCha20 & Poly1305): https://datatracker.ietf.org/doc/html/rfc8439#section-2.8
- Cloudflare explainer: https://blog.cloudflare.com/it-takes-two-to-chacha-poly/

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
  - [Encrypt and authenticate](#encrypt-and-authenticate)
  - [Decrypt and verify](#decrypt-and-verify)
- [API reference](#api-reference)
  - [`AeadChaCha20Poly1305`](#aeadchacha20poly1305)
- [Behavior notes](#behavior-notes)
- [Best practices](#best-practices)
- [Development](#development)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building and testing this repository.
- Target runtime/framework for the package: **.NET 8** (`net8.0`).

The repository includes a `global.json` to pin the SDK family used for development.

---

## Installation

### NuGet Package Manager (CLI)

```bash
dotnet add package AeadChaCha20Poly1305.NetCore
```

### Package Manager Console

```powershell
Install-Package AeadChaCha20Poly1305.NetCore
```

### NuGet Gallery

- https://www.nuget.org/packages/AeadChaCha20Poly1305.NetCore/

---

## Quick start

### Encrypt and authenticate

```csharp
using System;
using System.Security.Cryptography;
using AeadChaCha20Poly1305.NetCore;
using PinnedMemory;

var nonce = new byte[12];   // 96-bit nonce per RFC 8439
var keyBytes = new byte[32]; // 256-bit key
var plaintext = new byte[1024];
var associatedData = new byte[] { 0x20, 0x21, 0x22 };

RandomNumberGenerator.Fill(nonce);
RandomNumberGenerator.Fill(keyBytes);
RandomNumberGenerator.Fill(plaintext);

using var key = new PinnedMemory<byte>(keyBytes, false);
using var cipher = new AeadChaCha20Poly1305(key, nonce, associatedData);

cipher.UpdateBlock(plaintext, 0, plaintext.Length);

using var ciphertext = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
cipher.DoFinal(ciphertext, 0);

var tag = cipher.GetTag(); // 16-byte authentication tag
```

### Decrypt and verify

```csharp
// Reuse the same key, nonce, and associated data from encryption.
// Provide the tag obtained from the encryption phase.

cipher.Reset();
cipher.SetTag(tag!);
cipher.UpdateBlock(ciphertext, 0, ciphertext.Length);

using var decrypted = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
cipher.DoFinal(decrypted, 0);

// If tag verification fails, DoFinal throws ArgumentException.
```

For additional runnable examples, see `AeadChaCha20Poly1305.NetCore.Examples`.

---

## API reference

## `AeadChaCha20Poly1305`

### Constructor

```csharp
AeadChaCha20Poly1305(PinnedMemory<byte> key, byte[] nonce, byte[]? ad = null, int rounds = 20)
```

- `key` must be exactly **32 bytes**.
- `nonce` must be exactly **12 bytes**.
- `ad` is optional associated data and may be `null`.
- `rounds` must be **20** (RFC 8439 requirement).

### Core methods

```csharp
int GetLength()
byte[] GetBuffer()
int GetTagLength()
PinnedMemory<byte>? GetTag()
void SetTag(PinnedMemory<byte> value)
void Update(byte value)
void UpdateBlock(byte[] value, int offset, int length)
void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
void DoFinal(PinnedMemory<byte> output, int offset)
void DoFinal(byte[] output, int offset)
void Reset()
void Dispose()
```

---

## Behavior notes

- `GetLength()` returns the length of buffered input data (ciphertext or plaintext length).
- `GetTagLength()` returns **16** bytes.
- If no tag is set, `DoFinal(...)` performs **encryption** and populates an authentication tag.
- If a tag is set via `SetTag(...)`, `DoFinal(...)` performs **decryption** and verifies the provided tag.
- On tag verification failure, decryption throws `ArgumentException`.
- `Reset()` clears buffered data and tag state but retains key/nonce/ad configuration.
- `Dispose()` zeroes key/nonce and releases owned resources.

---

## Best practices

### 1) Treat nonces as unique per key

Never reuse the same nonce with the same key across different messages.

### 2) Keep associated data consistent

The exact same associated data bytes used for encryption must be supplied during decryption.

### 3) Handle tags carefully

Always store/transmit the full 16-byte tag and set it before decryption.

### 4) Use `using` and dispose promptly

Dispose key and cipher instances as soon as they are no longer needed.

### 5) Validate offsets/lengths in caller code

Ensure destination buffers are sized to `GetLength()` before calling `DoFinal(...)`.

---

## Development

### Build

```bash
dotnet build AeadChaCha20Poly1305.NetCore.sln
```

### Test

```bash
dotnet test AeadChaCha20Poly1305.NetCore.sln
```

---

## Security notes

- This library relies on .NET cryptography primitives (`ChaCha20Poly1305`) for AEAD operations.
- Authentication must always be verified before trusting decrypted plaintext.
- Keep key material secret and prefer memory-safe handling patterns (`PinnedMemory`, short-lived buffers, disposal).

---

## License

MIT
