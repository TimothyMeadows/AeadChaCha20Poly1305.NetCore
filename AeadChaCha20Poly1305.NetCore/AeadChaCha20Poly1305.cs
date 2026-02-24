using System;
using System.IO;
using System.Security.Cryptography;
using PinnedMemory;

namespace AeadChaCha20Poly1305.NetCore;

/*
 * This implementation follows RFC 8439 section 2.8.
 */
public sealed class AeadChaCha20Poly1305 : IDisposable
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;
    private readonly byte[] _nonce;
    private readonly byte[] _ad;
    private readonly MemoryStream _buffer = new();

    private PinnedMemory<byte>? _tag;
    private bool _disposed;

    public AeadChaCha20Poly1305(PinnedMemory<byte> key, byte[] nonce, byte[]? ad = null, int rounds = 20)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(nonce);

        if (rounds != 20)
        {
            throw new ArgumentOutOfRangeException(nameof(rounds), "RFC 8439 ChaCha20-Poly1305 requires 20 rounds.");
        }

        if (key.Length != KeySize)
        {
            throw new ArgumentException("key must be 256 bit (32 bytes)", nameof(key));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException("nonce must be 96 bit (12 bytes) per RFC 8439.", nameof(nonce));
        }

        _key = key.ToArray();
        _nonce = (byte[])nonce.Clone();
        _ad = ad is null ? Array.Empty<byte>() : (byte[])ad.Clone();
    }

    public int GetLength() => checked((int)_buffer.Length);

    public byte[] GetBuffer() => _buffer.ToArray();

    public int GetTagLength() => TagSize;

    public PinnedMemory<byte>? GetTag() => _tag;

    public void SetTag(PinnedMemory<byte> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != TagSize)
        {
            throw new ArgumentException($"tag must be {TagSize} bytes.", nameof(value));
        }

        _tag = value;
    }

    public void Update(byte value)
    {
        ThrowIfDisposed();
        _buffer.WriteByte(value);
    }

    public void UpdateBlock(byte[] value, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(value);
        ThrowIfDisposed();
        ValidateRange(value.Length, offset, length);
        _buffer.Write(value, offset, length);
    }

    public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(value);
        ThrowIfDisposed();
        ValidateRange(value.Length, offset, length);

        var input = value.ToArray();
        _buffer.Write(input, offset, length);
        CryptographicOperations.ZeroMemory(input);
    }

    public void DoFinal(PinnedMemory<byte> output, int offset)
    {
        ArgumentNullException.ThrowIfNull(output);
        ThrowIfDisposed();

        var data = _buffer.ToArray();
        ValidateRange(output.Length, offset, data.Length);

        if (_tag is null)
        {
            var cipher = new byte[data.Length];
            var tag = new byte[TagSize];

            using var aead = new ChaCha20Poly1305(_key);
            aead.Encrypt(_nonce, data, cipher, tag, _ad);

            WriteResult(output, offset, cipher);
            _tag = new PinnedMemory<byte>(tag, false);
            CryptographicOperations.ZeroMemory(cipher);
        }
        else
        {
            var plain = new byte[data.Length];

            using var aead = new ChaCha20Poly1305(_key);
            try
            {
                aead.Decrypt(_nonce, data, _tag.ToArray(), plain, _ad);
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("tag does not match data tag!", nameof(_tag), ex);
            }

            WriteResult(output, offset, plain);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public void DoFinal(byte[] output, int offset)
    {
        ArgumentNullException.ThrowIfNull(output);
        ThrowIfDisposed();

        var data = _buffer.ToArray();
        ValidateRange(output.Length, offset, data.Length);

        if (_tag is null)
        {
            var tag = new byte[TagSize];

            using var aead = new ChaCha20Poly1305(_key);
            aead.Encrypt(_nonce, data, output.AsSpan(offset, data.Length), tag, _ad);

            _tag = new PinnedMemory<byte>(tag, false);
        }
        else
        {
            using var aead = new ChaCha20Poly1305(_key);
            try
            {
                aead.Decrypt(_nonce, data, _tag.ToArray(), output.AsSpan(offset, data.Length), _ad);
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("tag does not match data tag!", nameof(_tag), ex);
            }
        }
    }

    public void Reset()
    {
        ThrowIfDisposed();
        _buffer.SetLength(0);
        _tag = null;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_nonce);
        _buffer.SetLength(0);
        _buffer.Dispose();
        _tag?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private static void WriteResult(PinnedMemory<byte> destination, int offset, byte[] source)
    {
        for (var i = 0; i < source.Length; i++)
        {
            destination[offset + i] = source[i];
        }
    }

    private static void ValidateRange(int totalLength, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > totalLength - length)
        {
            throw new ArgumentOutOfRangeException($"Invalid offset/length range: offset={offset}, length={length}.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
