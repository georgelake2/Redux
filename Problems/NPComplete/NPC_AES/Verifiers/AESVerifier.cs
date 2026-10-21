using API.Interfaces;

namespace API.Problems.NPComplete.NPC_AES.Verifiers;

/// <summary>
/// Checks a proposed key (and message) with one AES encryption: the key must agree with every bit Eve knows, and
/// encrypting the known plaintext, or the proposed message padded to one block, must give exactly the intercepted
/// ciphertext. Easy to check, hard to find: that gap is what the key search pays for.
/// </summary>
class AESVerifier : IVerifier<AES> {

    public const string CertificateGrammar =
        "the full key as 32 hex digits, agreeing with the known key bits; for a message instance, the key and the " +
        "message as (keyHex,\"TEXT\") (letters and spaces, any case)";
    public const string CertificateExample = "(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLD\")";

    // --- Fields ---
    public string verifierName { get; } = "Default AES Verifier";
    public string verifierDefinition { get; } =
        "Checks that the proposed key agrees with every key bit the attacker knows, then encrypts with it: the known " +
        "plaintext, or for a message the proposed message padded to one 16-byte block. The key is correct if the " +
        "result is exactly the intercepted ciphertext.";
    public string source { get; } =
        "National Institute of Standards and Technology (2001, updated 2023). Advanced Encryption Standard (AES). " +
        "FIPS PUB 197.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public string certificate { get; } = "";

    // --- Constructors ---
    public AESVerifier() { }

    // --- Methods ---

    public bool verify(AES problem, string certificate) {
        (byte[] key, string? message) = Parse(problem, certificate);
        if (!problem.MatchesKnownBits(key))
            return false;
        if (message is null)
            return AESCipher.Encrypt(problem.knownPlaintext!, key).SequenceEqual(problem.ciphertext);
        if (message.Length is 0 or > AESMessage.MaxLength)
            return false; // cannot be the message in one block
        return AESCipher.Encrypt(AESMessage.Pad(message), key).SequenceEqual(problem.ciphertext);
    }

    /// <summary>Reads "keyHex" for an Eve's-view instance, or "(keyHex,"TEXT")" (quotes optional) for a message instance.</summary>
    private static (byte[] Key, string? Message) Parse(AES problem, string certificate) {
        string text = certificate.Trim();
        if (!problem.isMessage)
            return (ParseKey(problem, certificate, text), null);

        if (text.Length < 2 || text[0] != '(' || text[^1] != ')' || !text.Contains(','))
            throw new CertificateParseException(problem, certificate, "expected the key and the message as (keyHex,\"TEXT\")");
        string[] parts = text[1..^1].Split(',', 2);
        byte[] key = ParseKey(problem, certificate, parts[0].Trim());
        string message = parts[1].Trim();
        if (message.Length >= 2 && message[0] == '"' && message[^1] == '"')
            message = message[1..^1];
        foreach (char ch in message) {
            if (!AESMessage.IsAllowed(ch))
                throw new CertificateParseException(problem, certificate,
                    $"'{ch}' is not a letter or space, so it cannot be part of the message");
        }
        return (key, message);
    }

    private static byte[] ParseKey(AES problem, string certificate, string text) =>
        AES.TryParseBlock(text)
        ?? throw new CertificateParseException(problem, certificate, "the key must be 32 hex digits (16 bytes)");
}
