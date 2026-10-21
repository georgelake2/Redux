using System.Text;
using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_AES;

/// <summary>
/// How a message becomes one 16-byte AES block in message mode, and how an attacker recognises it again. The
/// message is upper-cased, written as ASCII bytes and padded the standard way (PKCS#7): n missing bytes are filled
/// with n copies of the byte n. Padding always adds at least one byte, so one block holds at most 15 characters.
/// The alphabet is the one RSA and Diffie-Hellman use (letters and spaces, see <see cref="RSAAlphabet"/>).
/// </summary>
static class AESMessage {

    public const int MaxLength = AESCipher.BlockSize - 1;

    /// <summary>The padded block for a message of 1 to 15 letters and spaces (any case).</summary>
    public static byte[] Pad(string message) {
        if (message.Length is 0 or > MaxLength)
            throw new ArgumentException($"a message must have 1 to {MaxLength} characters", nameof(message));
        byte padding = (byte)(AESCipher.BlockSize - message.Length);
        var block = new byte[AESCipher.BlockSize];
        Encoding.ASCII.GetBytes(message.ToUpperInvariant()).CopyTo(block, 0);
        Array.Fill(block, padding, message.Length, padding);
        return block;
    }

    /// <summary>
    /// The message in a decrypted block, or null if the block does not read as one: the padding must be valid
    /// and every other byte an upper-case letter or a space. A wrong key gives 16 effectively random bytes, which
    /// pass this test with a chance of about 1 in 10^16 or less, so in practice only the right key passes.
    /// </summary>
    public static string? Read(byte[] block) {
        int padding = block[^1];
        if (padding < 1 || padding > MaxLength)
            return null;
        for (int i = block.Length - padding; i < block.Length; i++) {
            if (block[i] != padding)
                return null;
        }
        var text = new StringBuilder();
        for (int i = 0; i < block.Length - padding; i++) {
            char ch = (char)block[i];
            if (ch != ' ' && ch is not (>= 'A' and <= 'Z'))
                return null;
            text.Append(ch);
        }
        return text.ToString();
    }

    public static bool IsAllowed(char ch) => RSAAlphabet.IsEncodable(ch);
}
