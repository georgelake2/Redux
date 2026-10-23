using System.Globalization;
using API.Interfaces;
using API.Problems.NPComplete.NPC_AES.Solvers;
using API.Problems.NPComplete.NPC_AES.Verifiers;
using API.Problems.NPComplete.NPC_AES.Visualizations;

namespace API.Problems.NPComplete.NPC_AES;

/// <summary>
/// AES-128 key search from an eavesdropper's point of view: Eve has an encrypted block and all of the key except
/// its last k bits, and searches the 2^k candidates for the one that fits. Real AES keys have no known bits, and
/// 2^128 candidates is far beyond any computer; hiding only k bits makes the search small enough to watch. This is
/// the search Grover's algorithm speeds up from about 2^k tries to about 2^(k/2).
///
/// An instance comes in two forms:
/// <list type="bullet">
/// <item><c>(knownKeyHex,k,plaintextHex,ciphertextHex)</c>: Eve's view, a known-plaintext attack. The last k bits of
/// the known key must be zero, standing for the bits Eve does not know. The answer is the key.</item>
/// <item><c>(keyHex,k,"TEXT")</c>: message mode. The student plays Alice: the problem pads and encrypts the
/// message under the key and keeps only what Eve sees (the ciphertext and the key with its last k bits hidden).
/// Eve recognises the right key because the block it decrypts to reads as a message. The answer is the key and
/// the message.</item>
/// </list>
/// </summary>
class AES : IProblem<AESBruteForceKeySearchSolver, AESVerifier, AESKnowledgeTableVisualization> {

    // --- Fields ---
    public string problemName { get; } = "AES";
    public string problemLink { get; } = "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard";
    public string formalDefinition { get; } =
        "AES = {<K, k, P, C> | some key K' that agrees with K except in its last k bits has AES-128_K'(P) = C}";
    public string problemDefinition { get; } =
        "Recover an AES-128 key, and with it the message, when the attacker knows every bit of the key except the " +
        "last k. AES has no mathematical shortcut like factoring: the only attack is to try every candidate for the " +
        "missing bits, 2^k of them, until one decrypts the intercepted ciphertext.";
    public string inputDescription { get; } =
        "Either Eve's view: the known key bits in hex (the last k bits zero), k, and a known plaintext and its " +
        "ciphertext in hex; or a message to send: the full key in hex, k, and a message in quotes, which is encrypted " +
        "under the key";
    public string outputDescription { get; } =
        "The full key in hex; for a message, the key and the recovered message, as (keyHex,\"TEXT\")";
    public string source { get; } =
        "National Institute of Standards and Technology (2001, updated 2023). Advanced Encryption Standard (AES). " +
        "FIPS PUB 197. Daemen, J., and Rijmen, V. (2002). The Design of Rijndael. Springer.";
    public string sourceLink { get; } = "https://doi.org/10.6028/NIST.FIPS.197-upd1";
    // The walkthrough on georgelake.dev, opened on its high-school version (a switch on the page shows the CS one).
    public string walkthroughLink { get; } = "https://georgelake.dev/research/guides/aes/#hs";
    public string sourceFile { get; } = SourceFile.Path();
    public string wikiName { get; } = "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard";
    public string[] contributors { get; } = { "George Lake" };

    public const string InstanceGrammar = "(knownKeyHex,k,plaintextHex,ciphertextHex) or (keyHex,k,\"TEXT\")";

    /// <summary>
    /// The largest k accepted: 2^20, about a million candidate keys, takes a few seconds; every 4 more bits
    /// multiply that by 16.
    /// </summary>
    public const int MaxUnknownBits = 20;

    // Message mode with the FIPS 197 example key, so the rounds can be checked against the standard. With k = 8
    // Eve knows all but the last byte (3c): 256 candidates, found on the 61st try.
    private static readonly string _defaultInstance = "(2b7e151628aed2a6abf7158809cf4f3c,8,\"Hello World\")";
    public string defaultInstance { get; } = _defaultInstance;
    public string instanceFormat { get; } =
        $"Format: {InstanceGrammar}. Keys and blocks are 32 hex digits (16 bytes); k, the number of key bits Eve " +
        $"does not know, is 1 to {MaxUnknownBits}. Eve's view: the last k bits of knownKeyHex must be zero. Message " +
        $"mode: a message of 1 to {AESMessage.MaxLength} letters and spaces, which fits in one AES block. Examples: " +
        $"(2b7e151628aed2a6abf7158809cf4f00,8,3243f6a8885a308d313198a2e0370734,3925841d02dc09fbdc118597196a0b32) " +
        $"and {_defaultInstance}";
    public string certificateFormat { get; } =
        $"Format: {AESVerifier.CertificateGrammar} Example: {AESVerifier.CertificateExample}";
    public string instance { get; set; } = string.Empty;

    // Declared, not derived. A proposed key is easy to check (one encryption); nothing better than trying keys
    // is known for AES.
    public ComplexityClass complexityClass { get; } = ComplexityClass.NP;
    // Declared, not derived. Redux has no cryptography category yet; filed with RSA and Diffie-Hellman.
    public ProblemType problemType { get; } = ProblemType.AlgebraAndNumberTheory;

    public AESBruteForceKeySearchSolver defaultSolver { get; } = new AESBruteForceKeySearchSolver();
    public AESVerifier defaultVerifier { get; } = new AESVerifier();
    public AESKnowledgeTableVisualization defaultVisualization { get; } = new AESKnowledgeTableVisualization();

    // --- Properties: what Eve sees ---

    /// <summary>The key with its last k bits set to zero: everything Eve knows about it.</summary>
    public byte[] knownKey { get; }

    /// <summary>k, the number of key bits Eve does not know (the last k bits of the key).</summary>
    public int unknownBits { get; }

    /// <summary>The intercepted ciphertext block.</summary>
    public byte[] ciphertext { get; }

    /// <summary>In Eve's view, the known plaintext; null in message mode, where the message is the secret.</summary>
    public byte[]? knownPlaintext { get; }

    /// <summary>True for a (keyHex,k,"TEXT") instance, whose answer includes the recovered message.</summary>
    public bool isMessage { get; }

    /// <summary>How many candidate keys there are: 2^k.</summary>
    public long candidateCount => 1L << unknownBits;

    // --- Constructors ---

    public AES() : this(_defaultInstance) {
    }

    /// <summary>
    /// Reads "(knownKeyHex,k,plaintextHex,ciphertextHex)" or "(keyHex,k,"TEXT")". Parsed by hand because the
    /// instance parser (SPADE) has no quoted-text type. In message mode the full key is used to encrypt and then
    /// dropped; only its known bits are kept.
    /// </summary>
    public AES(string instance) {
        this.instance = instance;

        string body = instance.Trim();
        if (body.Length < 2 || body[0] != '(' || body[^1] != ')')
            throw Invalid("expected (knownKeyHex,k,plaintextHex,ciphertextHex) or (keyHex,k,\"TEXT\") in parentheses");
        string[] parts = body[1..^1].Split(',', 4);
        bool messageMode = parts.Length >= 3 && parts[2].Trim().StartsWith('"');
        if (parts.Length != 4 && !messageMode)
            throw Invalid("expected four values (knownKeyHex,k,plaintextHex,ciphertextHex) or three values (keyHex,k,\"TEXT\")");

        byte[] key = ParseBlock(parts[0].Trim(), messageMode ? "the key" : "the known key");
        string kText = parts[1].Trim();
        if (!int.TryParse(kText, NumberStyles.None, CultureInfo.InvariantCulture, out int k))
            throw Invalid($"k must be a whole number, got '{kText}'");
        if (k < 1 || k > MaxUnknownBits)
            throw Invalid($"k must be 1 to {MaxUnknownBits}, got k = {k}");
        unknownBits = k;

        if (messageMode) {
            isMessage = true;
            // A comma inside the message splits it, so put it back together (ParseMessage then rejects the comma).
            ciphertext = AESCipher.Encrypt(AESMessage.Pad(ParseMessage(string.Join(",", parts[2..]).Trim())), key);
            knownKey = WithMissingBits(key, 0);
            return;
        }

        if (!WithMissingBits(key, 0).SequenceEqual(key))
            throw Invalid($"the last k = {k} bits of the known key must be zero: they are the bits Eve does not know");
        knownKey = key;
        knownPlaintext = ParseBlock(parts[2].Trim(), "the plaintext");
        ciphertext = ParseBlock(parts[3].Trim(), "the ciphertext");
    }

    // --- Methods ---

    /// <summary>The known key with its last k bits replaced by <paramref name="missingBits"/>.</summary>
    public byte[] CandidateKey(long missingBits) => WithMissingBits(knownKey, missingBits);

    /// <summary>Whether a full key agrees with every bit Eve knows.</summary>
    public bool MatchesKnownBits(byte[] key) => WithMissingBits(key, 0).SequenceEqual(knownKey);

    /// <summary>The value of a key's last k bits.</summary>
    public long MissingBitsOf(byte[] key) {
        long value = 0;
        for (int i = AESCipher.KeySize - 3; i < AESCipher.KeySize; i++)
            value = (value << 8) | key[i];
        return value & (candidateCount - 1);
    }

    /// <summary>The known key in hex, with "?" for every hex digit that holds an unknown bit.</summary>
    public string KnownKeyText() {
        int hiddenDigits = (unknownBits + 3) / 4;
        string hex = Hex(knownKey);
        return hex[..^hiddenDigits] + new string('?', hiddenDigits);
    }

    /// <summary>The missing bits as text: hex, and binary when k is not a whole number of hex digits.</summary>
    public string MissingBitsText(long missingBits) {
        string hex = missingBits.ToString("x" + ((unknownBits + 3) / 4), CultureInfo.InvariantCulture);
        string binary = Convert.ToString(missingBits, 2).PadLeft(unknownBits, '0');
        return $"{hex} (binary {binary})";
    }

    /// <summary>The answer for a recovered key: the key in hex, or (keyHex,"TEXT") in message mode.</summary>
    public string Answer(byte[] key, string? message) => isMessage ? $"({Hex(key)},\"{message}\")" : Hex(key);

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>Reads exactly 32 hex digits as 16 bytes, or returns null.</summary>
    public static byte[]? TryParseBlock(string text) {
        if (text.Length != 2 * AESCipher.BlockSize || !text.All(Uri.IsHexDigit))
            return null;
        return Convert.FromHexString(text);
    }

    private byte[] WithMissingBits(byte[] key, long missingBits) {
        byte[] result = (byte[])key.Clone();
        long mask = candidateCount - 1;
        // k is at most 20, so the unknown bits all sit in the last three bytes.
        for (int i = 0; i < 3; i++) {
            int index = AESCipher.KeySize - 1 - i;
            int byteMask = (int)((mask >> (8 * i)) & 0xff);
            int bits = (int)((missingBits >> (8 * i)) & 0xff);
            result[index] = (byte)((result[index] & ~byteMask) | (bits & byteMask));
        }
        return result;
    }

    private byte[] ParseBlock(string text, string name) =>
        TryParseBlock(text) ?? throw Invalid($"{name} must be 32 hex digits (16 bytes), got '{text}'");

    private string ParseMessage(string quoted) {
        if (quoted.Length < 2 || quoted[0] != '"' || !quoted.EndsWith('"'))
            throw Invalid("the message must be enclosed in double quotes");
        string message = quoted[1..^1];
        if (message.Length == 0)
            throw Invalid("the message is empty");
        if (message.Length > AESMessage.MaxLength)
            throw Invalid($"the message must fit in one AES block: at most {AESMessage.MaxLength} characters, got {message.Length}");
        foreach (char ch in message) {
            if (!AESMessage.IsAllowed(ch))
                throw Invalid($"'{ch}' cannot be encrypted: a message may contain only letters A-Z and spaces");
        }
        return message;
    }

    private ProblemParseException Invalid(string reason) => new(problemName, instance, reason);
}
