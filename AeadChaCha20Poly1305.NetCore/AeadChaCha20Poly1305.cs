using System;
using System.Linq;
using System.Text;
using PinnedMemory;

namespace AeadChaCha20Poly1305.NetCore
{
    /*
     * This implementation was created from
     * https://tools.ietf.org/html/rfc7539#section-2.8
     */
    public class AeadChaCha20Poly1305 : IDisposable
    {
        private readonly ChaCha20.NetCore.ChaCha20 _chacha;
        private readonly Poly1305.NetCore.Poly1305 _poly1305;
        private PinnedMemory<byte> _polyKey;
        private PinnedMemory<byte> _tag;
        private readonly PinnedMemory<byte> _ad;

        private const int BlockSize = 16;

        /** Polynomial key */
        private uint r0, r1, r2, r3, r4;

        /** Precomputed 5 * r[1..4] */
        private uint s1, s2, s3, s4;

        /** Encrypted nonce */
        private uint k0, k1, k2, k3;

        public AeadChaCha20Poly1305(PinnedMemory<byte> key, byte[] nonce, byte[] ad = null, int rounds = 20)
        {
            if (key.Length != 32)
                throw new ArgumentException("key must be 256bit (32 bytes)");

            if (nonce.Length != 16)
                throw new ArgumentException("nonce must be 128bit (16 bytes)");

            // Poly1305 Key
            SetKey(key, nonce);
            _poly1305 = new Poly1305.NetCore.Poly1305(_polyKey);

            // ChaCha20 Key, counter should default to 1 on construction
            _chacha = new ChaCha20.NetCore.ChaCha20(key, nonce, rounds);

            ad ??= new byte[BlockSize]; // empty block if not used.
            Pad(ref ad); // pad if less than multiple of 16
            _ad = new PinnedMemory<byte>(ad, false);
        }

        public int GetLength()
        {
            return _chacha.GetLength();
        }

        public byte[] GetBuffer()
        {
            return _chacha.GetBuffer();
        }

        public int GetTagLength()
        {
            return _poly1305.GetLength();
        }

        public PinnedMemory<byte> GetTag()
        {
            return _tag;
        }

        public void SetTag(PinnedMemory<byte> value)
        {
            _tag = value;
        }

        public void Update(byte value)
        {
            _chacha.Update(value);
        }

        public void UpdateBlock(byte[] value, int offset, int length)
        {
            _chacha.UpdateBlock(value, offset, length);
        }

        public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
        {
            _chacha.UpdateBlock(value, offset, length);
        }

        public void DoFinal(PinnedMemory<byte> output, int offset)
        {
            var length = _chacha.GetLength();
            if (length < BlockSize)
                throw new ArgumentException($"a single block can't be smaller than a block size of '{BlockSize}'.");

            if (_tag == null)
                DoEncryptionAndAuthentication(output, offset);
            else
                DoDecryptionAndAuthentication(output, offset);
        }

        public void DoFinal(byte[] output, int offset)
        {
            var length = _chacha.GetLength();
            if (length < BlockSize)
                throw new ArgumentException($"a single block can't be smaller than a block size of '{BlockSize}'.");

            if (_tag == null)
                DoEncryptionAndAuthentication(output, offset);
            else
                DoDecryptionAndAuthentication(output, offset);
        }

        public void Reset()
        {
            _chacha.Reset();
            _tag = null;
        }

        public void Dispose()
        {
            _chacha?.Dispose();
            _poly1305?.Dispose();
            _polyKey?.Dispose();
            _ad?.Dispose();
        }

        private void DoEncryptionAndAuthentication(PinnedMemory<byte> output, int offset)
        {
            _chacha.DoFinal(output, offset);
            var aadLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(_ad.Length), ref aadLength);

            var cipherLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(output.Length), ref cipherLength);

            var aad = Concat(Concat(Concat(_ad.ToArray(), output.ToArray()), aadLength), cipherLength);
            _tag = new PinnedMemory<byte>(new byte[_poly1305.GetLength()]);
            _poly1305.UpdateBlock(aad, 0, aad.Length);
            _poly1305.DoFinal(_tag, 0);
        }

        private void DoEncryptionAndAuthentication(byte[] output, int offset)
        {
            _chacha.DoFinal(output, offset);
            var aadLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(_ad.Length), ref aadLength);

            var cipherLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(output.Length), ref cipherLength);

            var aad = Concat(Concat(Concat(_ad.ToArray(), output), aadLength), cipherLength);
            _tag = new PinnedMemory<byte>(new byte[_poly1305.GetLength()]);
            _poly1305.UpdateBlock(aad, 0, aad.Length);
            _poly1305.DoFinal(_tag, 0);
        }

        private void DoDecryptionAndAuthentication(PinnedMemory<byte> output, int offset)
        {
            var aadLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(_ad.Length), ref aadLength);

            var cipherLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(output.Length), ref cipherLength);

            var aad = Concat(Concat(Concat(_ad.ToArray(), _chacha.GetBuffer()), aadLength), cipherLength);
            var expected = new PinnedMemory<byte>(new byte[_poly1305.GetLength()]);
            _poly1305.UpdateBlock(aad, 0, aad.Length);
            _poly1305.DoFinal(expected, 0);

            if (!expected.ToArray().SequenceEqual(_tag.ToArray()))
                throw new ArgumentException("tag does not match data tag!");

            _chacha.DoFinal(output, offset);
        }

        private void DoDecryptionAndAuthentication(byte[] output, int offset)
        {
            var aadLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(_ad.Length), ref aadLength);

            var cipherLength = new byte[4];
            UInt32_To_LE(Convert.ToUInt32(output.Length), ref cipherLength);

            var aad = Concat(Concat(Concat(_ad.ToArray(), _chacha.GetBuffer()), aadLength), cipherLength);
            var expected = new PinnedMemory<byte>(new byte[_poly1305.GetLength()]);
            _poly1305.UpdateBlock(aad, 0, aad.Length);
            _poly1305.DoFinal(expected, 0);

            if (!expected.ToArray().SequenceEqual(_tag.ToArray()))
                throw new ArgumentException("tag does not match data tag!");

            _chacha.DoFinal(output, offset);
        }

        private void SetKey(PinnedMemory<byte> key, byte[] nonce)
        {
            if (key.Length != 32)
                throw new ArgumentException("Poly1305 key must be 256 bits.");

            if (nonce == null || nonce.Length != BlockSize)
                throw new ArgumentException("Poly1305 requires a 128 bit IV.");

            // Extract r portion of key (and "clamp" the values)
            var t0 = LE_To_UInt32(key, 0);
            var t1 = LE_To_UInt32(key, 4);
            var t2 = LE_To_UInt32(key, 8);
            var t3 = LE_To_UInt32(key, 12);

            // NOTE: The masks perform the key "clamping" implicitly
            r0 =   t0                      & 0x03FFFFFFU;
            r1 = ((t0 >> 26) | (t1 <<  6)) & 0x03FFFF03U;
            r2 = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FFU;
            r3 = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFFU;
            r4 =  (t3 >>  8)               & 0x000FFFFFU;

            // Precompute multipliers
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            // Compute encrypted nonce with chacha20
            _polyKey = key.Clone();

            using var cipher = new ChaCha20.NetCore.ChaCha20(_polyKey, nonce);
            cipher.UpdateBlock(nonce, 0, BlockSize);
            cipher.DoFinal(_polyKey, 0);
            cipher.Reset();

            k0 = LE_To_UInt32(_polyKey,  0);
            k1 = LE_To_UInt32(_polyKey, 4);
            k2 = LE_To_UInt32(_polyKey, 8);
            k3 = LE_To_UInt32(_polyKey, 12);
        }

        private static void Pad(ref byte[] source)
        {
            var len = (source.Length + 16 - 1) / 16 * 16;
            Array.Resize(ref source, len);
        }

        private void UInt32_To_LE(uint n, PinnedMemory<byte> bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private void UInt32_To_LE(uint value, ref byte[] output)
        {
            output[0] = (byte) value;
            output[1] = (byte) (value >> 8);
            output[2] = (byte) (value >> 16);
            output[3] = (byte) (value >> 24);
        }

        private uint LE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private uint LE_To_UInt32(PinnedMemory<byte> bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private byte[] Concat(byte[] source, byte[] destination, int sourceLength = 0, int destinationLength = 0)
        {
            var expandSourceLength = sourceLength > 0 ? sourceLength : source.Length;
            var expandDestinationLength = destinationLength > 0 ? destinationLength : destination.Length;
            var expanded = new byte[expandSourceLength + expandDestinationLength];

            Array.Copy(source, 0, expanded, 0, expandSourceLength);
            Array.Copy(destination, 0, expanded, expandSourceLength, expandDestinationLength);

            return expanded;
        }
    }
}
