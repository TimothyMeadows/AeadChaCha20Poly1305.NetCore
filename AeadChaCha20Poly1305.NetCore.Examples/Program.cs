using System;
using System.Linq;
using System.Security.Cryptography;
using PinnedMemory;

namespace AeadChaCha20Poly1305.NetCore.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
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
            var dataPin = new PinnedMemory<byte>(data, false);
            aeadChaCha20Poly1305.UpdateBlock(dataPin,0, dataPin.Length);

            using var output = new PinnedMemory<byte>(new byte[aeadChaCha20Poly1305.GetLength()]);
            aeadChaCha20Poly1305.DoFinal(output, 0);
            var tag = aeadChaCha20Poly1305.GetTag(); // Poly1305 tag used to authenticate cipher

            // Decryption / Authentication
            aeadChaCha20Poly1305.Reset();
            aeadChaCha20Poly1305.SetTag(tag);
            aeadChaCha20Poly1305.UpdateBlock(output,0, output.Length);

            using var plain = new PinnedMemory<byte>(new byte[aeadChaCha20Poly1305.GetLength()]);
            aeadChaCha20Poly1305.DoFinal(plain, 0);

            Console.WriteLine(data.SequenceEqual(plain.ToArray()));
        }
    }
}
