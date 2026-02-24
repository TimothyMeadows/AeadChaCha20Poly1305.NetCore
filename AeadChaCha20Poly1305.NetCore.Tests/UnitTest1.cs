using PinnedMemory;

namespace AeadChaCha20Poly1305.NetCore.Tests;

public class Rfc8439TestVectors
{
    private static readonly byte[] Key = HexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static readonly byte[] Nonce = HexToBytes("070000004041424344454647");
    private static readonly byte[] AdditionalData = HexToBytes("50515253c0c1c2c3c4c5c6c7");

    private static readonly byte[] Plaintext = HexToBytes(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");

    private static readonly byte[] Ciphertext = HexToBytes(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");

    private static readonly byte[] Tag = HexToBytes("1ae10b594f09e26a7e902ecbd0600691");

    [Fact]
    public void Encrypt_MatchesRfc8439Section2_8_2Vector()
    {
        using var keyPinned = new PinnedMemory<byte>(Key, false);
        using var cipher = new AeadChaCha20Poly1305(keyPinned, Nonce, AdditionalData);

        var output = new byte[Plaintext.Length];
        cipher.UpdateBlock(Plaintext, 0, Plaintext.Length);
        cipher.DoFinal(output, 0);

        Assert.Equal(Ciphertext, output);
        Assert.Equal(Tag, cipher.GetTag()!.ToArray());
    }

    [Fact]
    public void Decrypt_MatchesRfc8439Section2_8_2Vector()
    {
        using var keyPinned = new PinnedMemory<byte>(Key, false);
        using var cipher = new AeadChaCha20Poly1305(keyPinned, Nonce, AdditionalData);
        using var expectedTagPinned = new PinnedMemory<byte>(Tag, false);
        using var output = new PinnedMemory<byte>(new byte[Ciphertext.Length]);

        cipher.SetTag(expectedTagPinned);
        cipher.UpdateBlock(Ciphertext, 0, Ciphertext.Length);
        cipher.DoFinal(output, 0);

        Assert.Equal(Plaintext, output.ToArray()[..Plaintext.Length]);
    }

    [Fact]
    public void Decrypt_WithTamperedTag_ThrowsArgumentException()
    {
        using var keyPinned = new PinnedMemory<byte>(Key, false);
        using var cipher = new AeadChaCha20Poly1305(keyPinned, Nonce, AdditionalData);

        var tamperedTag = (byte[])Tag.Clone();
        tamperedTag[^1] ^= 0xFF;

        using var tamperedTagPinned = new PinnedMemory<byte>(tamperedTag, false);
        var output = new byte[Ciphertext.Length];

        cipher.SetTag(tamperedTagPinned);
        cipher.UpdateBlock(Ciphertext, 0, Ciphertext.Length);

        var ex = Assert.Throws<ArgumentException>(() => cipher.DoFinal(output, 0));
        Assert.Equal("_tag", ex.ParamName);
    }

    private static byte[] HexToBytes(string hex)
    {
        return Convert.FromHexString(hex);
    }
}
