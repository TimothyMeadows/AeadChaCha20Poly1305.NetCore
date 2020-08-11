# AeadChaCha20Poly1305.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/AeadChaCha20Poly1305.NetCore.svg)](https://www.nuget.org/packages/AeadChaCha20Poly1305.NetCore/)

Implementation of AEAD_CHACHA20_POLY1305 an authenticated encryption with additional data algorithm using ChaCha20, and Poly1305 designed by D. J. Bernstein. Optimized for PinnedMemory, and .NET core.

You can read more about AEAD, ChaCha20, and Poly1305 using the resources below:
- https://tools.ietf.org/html/rfc7539#section-2.8
- https://blog.cloudflare.com/it-takes-two-to-chacha-poly/

# Install

From a command prompt
```bash
dotnet add package AeadChaCha20Poly1305.NetCore
```

```bash
Install-Package AeadChaCha20Poly1305.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/AeadChaCha20Poly1305.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var nonce = new byte[16];
var key = new byte[32];
var data = new byte[1024];

using var provider = new RNGCryptoServiceProvider();
provider.GetBytes(nonce);
provider.GetBytes(key);
provider.GetBytes(data);

using var keyPin = new PinnedMemory<byte>(key, false);
var aeadChaCha20Poly1305 = new AeadChaCha20Poly1305(keyPin, nonce, new byte[] { 32 });

// Encryption / Authentication
using var dataPin = new PinnedMemory<byte>(data, false);
eadChaCha20Poly1305.UpdateBlock(dataPin,0, dataPin.Length);

using var output = new PinnedMemory<byte>(new byte[aeadChaCha20Poly1305.GetLength()]);
aeadChaCha20Poly1305.DoFinal(output, 0);
var tag = aeadChaCha20Poly1305.GetTag(); // Poly1305 tag used to authenticate cipher

// Decryption / Authentication
aeadChaCha20Poly1305.Reset();
aeadChaCha20Poly1305.SetTag(tag);
aeadChaCha20Poly1305.UpdateBlock(output,0, output.Length);

using var plain = new PinnedMemory<byte>(new byte[aeadChaCha20Poly1305.GetLength()]);
aeadChaCha20Poly1305.DoFinal(plain, 0);
```

# Constructor

```csharp
AeadChaCha20Poly1305(PinnedMemory<byte> key, byte[] nonce, byte[] ad = null, int rounds = 20)
```

# Methods

Get the cipher output length.
```csharp
int GetLength()
```

Get the cipher authentication tag length.
```csharp
int GetTagLength()
```

Get the contents of the internal buffer, this can be used to compare data before encryption, or decryption.
```csharp
byte[] GetBuffer()
```

Update the cipher with a single byte.
```csharp
void Update(byte input)
```

Update the cipher with a pinned memory byte array.
```csharp
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```

Update the cipher with a byte array.
```csharp
void UpdateBlock(byte[] input, int inOff, int len)
```

Produce the final cipher outputting to pinned memory. Key & nonce remain.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Get the final cipher tag, this should be called after DoFinal.
```csharp
PinnedMemory<byte> GetTag()
```

Set the final cipher tag, this should be called before DoFinal, and is required for decryption.
```csharp
void SetTag(PinnedMemory<byte> value)
```

Reset the cipher back to it's initial state for further processing. Key remains until dispose is called.
```csharp
void Reset()
```

Clear key & nonce, reset cipher back to it's initial state.
```csharp
void Dispose()
```
