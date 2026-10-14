using System.Numerics;
using API.Interfaces;

namespace API.Problems.NPComplete.NPC_RSA.Verifiers;

/// <summary>
/// Checks a proposed plaintext by encrypting it with the public key. Verifying is a single modular
/// exponentiation per ciphertext even for a 2048-bit key, while finding the plaintext is not: that gap is
/// what puts RSA in NP.
/// </summary>
class RSAVerifier : IVerifier<RSA> {

    public const string CertificateGrammar =
        "the plaintext: a whole number m with 0 <= m < N and m^e mod N = c, or for a message instance the " +
        "message text (letters and spaces, any case)";
    public const string CertificateExample = "HELLO WORLD";

    // --- Fields ---
    public string verifierName { get; } = "Default RSA Verifier";
    public string verifierDefinition { get; } =
        "Encrypts the proposed plaintext with the public key and accepts it if it gives exactly the " +
        "intercepted ciphertext: m^e mod N = c with 0 <= m < N, or for a message, letter by letter.";
    public string source { get; } =
        "Rivest, R. L., Shamir, A., and Adleman, L. (1978). A Method for Obtaining Digital Signatures and " +
        "Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public string certificate { get; } = "";

    // --- Constructors ---
    public RSAVerifier() { }

    // --- Methods ---

    public bool verify(RSA problem, string certificate) =>
        problem.isMessage ? VerifyMessage(problem, certificate) : VerifyNumber(problem, certificate);

    private static bool VerifyNumber(RSA problem, string certificate) {
        if (!BigInteger.TryParse(certificate.Trim(), out BigInteger m))
            throw new CertificateParseException(problem, certificate, "the plaintext must be a whole number");

        // Out-of-range values are rejected even if they encrypt to c: m + N encrypts the same as m.
        if (m < 0 || m >= problem.modulus)
            return false;
        return BigInteger.ModPow(m, problem.publicExponent, problem.modulus) == problem.ciphertexts[0];
    }

    private static bool VerifyMessage(RSA problem, string certificate) {
        // Surrounding quotes are optional, so a message can be pasted back exactly as it was typed.
        string text = certificate.Length >= 2 && certificate[0] == '"' && certificate[^1] == '"'
            ? certificate[1..^1]
            : certificate;
        foreach (char ch in text) {
            if (!RSAAlphabet.IsEncodable(ch))
                throw new CertificateParseException(problem, certificate,
                    $"'{ch}' is not a letter or space, so it cannot be part of the message");
        }

        if (text.Length != problem.ciphertexts.Count)
            return false;
        for (int i = 0; i < text.Length; i++) {
            BigInteger encrypted = BigInteger.ModPow(RSAAlphabet.Encode(text[i]), problem.publicExponent, problem.modulus);
            if (encrypted != problem.ciphertexts[i])
                return false;
        }
        return true;
    }
}
