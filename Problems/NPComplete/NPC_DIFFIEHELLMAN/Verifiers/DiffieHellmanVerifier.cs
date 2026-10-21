using System.Numerics;
using API.Interfaces;
using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Verifiers;

/// <summary>
/// Checks a proposed answer using only the public values. A proposed shared secret or message could not be
/// checked on its own, so the answer carries Alice's private key: the verifier confirms g^a mod p = A, then (in
/// message mode) uses the key to get the shared secret, encrypts the proposed message with it and compares the
/// result with the intercepted ciphertexts.
/// </summary>
class DiffieHellmanVerifier : IVerifier<DIFFIEHELLMAN> {

    public const string CertificateGrammar =
        "Alice's private key a with 0 <= a <= p - 2 and g^a mod p = A; for a message instance, the key and the " +
        "message as (a,\"TEXT\") (letters and spaces, any case)";
    public const string CertificateExample = "(13,\"HELLO WORLD\")";

    // --- Fields ---
    public string verifierName { get; } = "Default Diffie-Hellman Verifier";
    public string verifierDefinition { get; } =
        "Checks that g^a mod p equals Alice's public value A for the proposed private key a. For a message, it then " +
        "computes the shared secret s = B^a mod p, encrypts the proposed message letter by letter with s, and checks " +
        "that the result is exactly the intercepted ciphertext.";
    public string source { get; } =
        "Diffie, W., and Hellman, M. E. (1976). New Directions in Cryptography. IEEE Transactions on Information " +
        "Theory, 22(6), 644-654.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public string certificate { get; } = "";

    // --- Constructors ---
    public DiffieHellmanVerifier() { }

    // --- Methods ---

    public bool verify(DIFFIEHELLMAN problem, string certificate) {
        (BigInteger key, string? message) = Parse(problem, certificate);
        if (!IsPrivateKey(problem, key))
            return false;
        return message is null || EncryptsToCiphertexts(problem, key, message);
    }

    /// <summary>Reads "a" for an Eve's-view instance, or "(a,"TEXT")" (quotes optional) for a message instance.</summary>
    private static (BigInteger Key, string? Message) Parse(DIFFIEHELLMAN problem, string certificate) {
        string text = certificate.Trim();
        if (!problem.isMessage) {
            if (!BigInteger.TryParse(text, out BigInteger key))
                throw new CertificateParseException(problem, certificate, "the private key must be a whole number");
            return (key, null);
        }

        if (text.Length < 2 || text[0] != '(' || text[^1] != ')' || !text.Contains(','))
            throw new CertificateParseException(problem, certificate, "expected the key and the message as (a,\"TEXT\")");
        string[] parts = text[1..^1].Split(',', 2);
        if (!BigInteger.TryParse(parts[0].Trim(), out BigInteger messageKey))
            throw new CertificateParseException(problem, certificate, "the private key must be a whole number");
        string message = parts[1].Trim();
        if (message.Length >= 2 && message[0] == '"' && message[^1] == '"')
            message = message[1..^1];
        foreach (char ch in message) {
            if (!RSAAlphabet.IsEncodable(ch))
                throw new CertificateParseException(problem, certificate,
                    $"'{ch}' is not a letter or space, so it cannot be part of the message");
        }
        return (messageKey, message);
    }

    private static bool IsPrivateKey(DIFFIEHELLMAN problem, BigInteger key) =>
        key >= 0 && key <= problem.modulus - 2 &&
        BigInteger.ModPow(problem.generator, key, problem.modulus) == problem.publicA;

    private static bool EncryptsToCiphertexts(DIFFIEHELLMAN problem, BigInteger key, string message) {
        if (message.Length != problem.ciphertexts.Count)
            return false;
        BigInteger s = BigInteger.ModPow(problem.publicB, key, problem.modulus);
        // Re-encrypting the proposed message (c = code x s mod p) is equivalent to decrypting the ciphertexts,
        // without needing s^-1.
        for (int i = 0; i < message.Length; i++) {
            if (RSAAlphabet.Encode(message[i]) * s % problem.modulus != problem.ciphertexts[i])
                return false;
        }
        return true;
    }
}
