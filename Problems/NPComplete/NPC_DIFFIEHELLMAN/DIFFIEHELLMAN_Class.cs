using System.Numerics;
using API.Interfaces;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Solvers;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Verifiers;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Visualizations;
using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN;

/// <summary>
/// Diffie-Hellman key exchange from an eavesdropper's point of view: given the public values p, g,
/// A = g^a and B = g^b, recover Alice's private key a, which gives the shared secret s = B^a mod p.
///
/// An instance comes in two forms:
/// <list type="bullet">
/// <item><c>(p,g,A,B)</c>: Eve's view of a key exchange. The answer is Alice's private key.</item>
/// <item><c>(p,g,a,b,"TEXT")</c>: message mode. The student plays Alice and Bob: the problem computes A, B and
/// s from the private keys, encrypts the message ElGamal style (each letter's code times s, mod p; letter codes
/// as in <see cref="RSAAlphabet"/>), and keeps only what Eve sees. The answer is the key and the message.</item>
/// </list>
///
/// Unlike RSA, a proposed shared secret or message cannot be checked from the public values alone (that is the
/// Decisional Diffie-Hellman assumption). A private key can: g^a mod p = A. So the answer always carries the key,
/// which is exactly what a discrete-log attack, classical or Shor's, has to find.
/// </summary>
class DIFFIEHELLMAN : IProblem<DHBruteForceDiscreteLogSolver, DiffieHellmanVerifier, DHKnowledgeTableVisualization> {

    // --- Fields ---
    public string problemName { get; } = "Diffie-Hellman";
    public string problemLink { get; } = "https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange";
    public string formalDefinition { get; } = "Diffie-Hellman = {<p, g, A, B> | some a with 0 <= a <= p - 2 has g^a = A (mod p)}";
    public string problemDefinition { get; } =
        "Recover a Diffie-Hellman shared secret using only what an eavesdropper sees: the prime p, the generator g " +
        "and the two public values A = g^a and B = g^b. Finding Alice's private key a (a discrete logarithm) gives " +
        "the shared secret s = B^a mod p, and with it any message Alice and Bob encrypted using s.";
    public string inputDescription { get; } =
        "Either Eve's view: p, g and the public values A and B; or a message to send: p, g, Alice's and Bob's private " +
        "keys a and b, and a message in quotes, which is encrypted with the shared secret (A = 1 ... Z = 26, space = 27)";
    public string outputDescription { get; } =
        "Alice's private key a, with g^a = A (mod p); for a message, the key and the recovered message, as (a,\"TEXT\")";
    public string source { get; } =
        "Diffie, W., and Hellman, M. E. (1976). New Directions in Cryptography. IEEE Transactions on Information " +
        "Theory, 22(6), 644-654. ElGamal, T. (1985). A Public Key Cryptosystem and a Signature Scheme Based on " +
        "Discrete Logarithms. IEEE Transactions on Information Theory, 31(4), 469-472.";
    public string sourceLink { get; } = "https://doi.org/10.1109/TIT.1976.1055638";
    // The walkthrough on georgelake.dev, opened on its high-school version (a switch on the page shows the CS one).
    public string walkthroughLink { get; } = "https://georgelake.dev/research/guides/dh/#hs";
    public string sourceFile { get; } = SourceFile.Path();
    public string wikiName { get; } = "https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange";
    public string[] contributors { get; } = { "George Lake" };

    public const string InstanceGrammar = "(p,g,A,B) or (p,g,a,b,\"TEXT\")";

    // Message mode, so a student sees a message recovered straight away. g = 2 generates every nonzero value
    // mod 59; A = 2^13 = 50, B = 2^23 = 47, shared secret s = 40.
    private static readonly string _defaultInstance = "(59,2,13,23,\"Hello World\")";
    public string defaultInstance { get; } = _defaultInstance;
    public string instanceFormat { get; } =
        $"Format: {InstanceGrammar}. Eve's view (p,g,A,B): modulus p >= 3, generator g with 1 < g < p, and the " +
        $"public values 1 <= A, B <= p - 1. Message mode (p,g,a,b,\"TEXT\"): the private keys 1 <= a, b <= p - 2 " +
        $"(positions 3 and 4 are private here, public in Eve's view) and a message of letters and spaces, which " +
        $"needs p > {RSAAlphabet.LargestCode}. Examples: (23,5,4,10) and {_defaultInstance}";
    public string certificateFormat { get; } =
        $"Format: {DiffieHellmanVerifier.CertificateGrammar} Example: {DiffieHellmanVerifier.CertificateExample}";
    public string instance { get; set; } = string.Empty;

    // Declared, not derived. A proposed private key is easy to check (one exponentiation); the discrete log is
    // not known to be NP-complete or in P, like integer factorization behind RSA.
    public ComplexityClass complexityClass { get; } = ComplexityClass.NP;
    // Declared, not derived. Redux has no cryptography category yet; Diffie-Hellman is modular arithmetic.
    public ProblemType problemType { get; } = ProblemType.AlgebraAndNumberTheory;

    public DHBruteForceDiscreteLogSolver defaultSolver { get; } = new DHBruteForceDiscreteLogSolver();
    public DiffieHellmanVerifier defaultVerifier { get; } = new DiffieHellmanVerifier();
    public DHKnowledgeTableVisualization defaultVisualization { get; } = new DHKnowledgeTableVisualization();

    // --- Properties: what Eve sees ---

    /// <summary>The modulus p.</summary>
    public BigInteger modulus { get; }

    /// <summary>The generator g.</summary>
    public BigInteger generator { get; }

    /// <summary>Alice's public value A = g^a mod p.</summary>
    public BigInteger publicA { get; }

    /// <summary>Bob's public value B = g^b mod p.</summary>
    public BigInteger publicB { get; }

    /// <summary>
    /// In message mode, the intercepted ciphertexts, one per letter: c = code x s mod p. Empty in Eve's-view
    /// instances. The private keys and the message are never stored.
    /// </summary>
    public IReadOnlyList<BigInteger> ciphertexts { get; }

    /// <summary>True for a (p,g,a,b,"TEXT") instance, whose answer includes the recovered message.</summary>
    public bool isMessage { get; }

    // --- Constructors ---

    public DIFFIEHELLMAN() : this(_defaultInstance) {
    }

    /// <summary>
    /// Reads "(p,g,A,B)" or "(p,g,a,b,"TEXT")". Only the format and the ranges are checked: whether p is prime
    /// and g a generator is something an attacker finds out, so the solvers report it. Parsed by hand because the
    /// instance parser (SPADE) has no quoted-text type.
    /// </summary>
    public DIFFIEHELLMAN(string instance) {
        this.instance = instance;

        string body = instance.Trim();
        if (body.Length < 2 || body[0] != '(' || body[^1] != ')')
            throw Invalid("expected (p,g,A,B) or (p,g,a,b,\"TEXT\") in parentheses");
        // At most five parts, so any comma inside a message lands in the fifth one (and is then rejected).
        string[] parts = body[1..^1].Split(',', 5);
        if (parts.Length != 4 && parts.Length != 5)
            throw Invalid("expected four values (p,g,A,B) or five values (p,g,a,b,\"TEXT\")");

        modulus = ParseInteger(parts[0].Trim(), "p");
        generator = ParseInteger(parts[1].Trim(), "g");
        if (modulus < 3)
            throw Invalid($"p must be at least 3, got {modulus}");
        if (generator <= 1 || generator >= modulus)
            throw Invalid($"g must satisfy 1 < g < p, got g = {generator}");

        if (parts.Length == 4) {
            publicA = ParseInteger(parts[2].Trim(), "A");
            publicB = ParseInteger(parts[3].Trim(), "B");
            if (publicA < 1 || publicA >= modulus)
                throw Invalid($"A must satisfy 1 <= A <= p - 1, got A = {publicA}");
            if (publicB < 1 || publicB >= modulus)
                throw Invalid($"B must satisfy 1 <= B <= p - 1, got B = {publicB}");
            ciphertexts = Array.Empty<BigInteger>();
            return;
        }

        // Message mode: positions 3 and 4 are the private keys.
        BigInteger a = ParseInteger(parts[2].Trim(), "a");
        BigInteger b = ParseInteger(parts[3].Trim(), "b");
        if (a < 1 || a > modulus - 2)
            throw Invalid($"Alice's private key a must satisfy 1 <= a <= p - 2, got a = {a}");
        if (b < 1 || b > modulus - 2)
            throw Invalid($"Bob's private key b must satisfy 1 <= b <= p - 2, got b = {b}");
        string message = ParseMessage(parts[4].Trim());

        isMessage = true;
        publicA = BigInteger.ModPow(generator, a, modulus);
        publicB = BigInteger.ModPow(generator, b, modulus);
        BigInteger sharedSecret = BigInteger.ModPow(publicB, a, modulus);
        ciphertexts = message.Select(ch => RSAAlphabet.Encode(ch) * sharedSecret % modulus).ToList();
    }

    // --- Methods ---

    /// <summary>
    /// The answer for a recovered private key and, in message mode, the recovered plaintext codes: the key alone,
    /// or (key,"TEXT") ("?" for a code that is not a letter, which a valid exchange never produces).
    /// </summary>
    public string Answer(BigInteger privateKey, IReadOnlyList<BigInteger> plaintexts) =>
        isMessage
            ? $"({privateKey},\"{new string(plaintexts.Select(m => RSAAlphabet.Decode(m) ?? '?').ToArray())}\")"
            : privateKey.ToString();

    private string ParseMessage(string quoted) {
        if (quoted.Length < 2 || quoted[0] != '"' || !quoted.EndsWith('"'))
            throw Invalid("the message must be enclosed in double quotes");
        string message = quoted[1..^1];
        if (message.Length == 0)
            throw Invalid("the message is empty");
        foreach (char ch in message) {
            if (!RSAAlphabet.IsEncodable(ch))
                throw Invalid($"'{ch}' cannot be encrypted: a message may contain only letters A-Z and spaces");
        }
        if (modulus <= RSAAlphabet.LargestCode)
            throw Invalid($"a message needs p > {RSAAlphabet.LargestCode} so every letter code is below p, got p = {modulus}");
        return message;
    }

    private BigInteger ParseInteger(string text, string name) {
        if (!BigInteger.TryParse(text, out BigInteger value))
            throw Invalid($"{name} must be a whole number, got '{text}'");
        return value;
    }

    private ProblemParseException Invalid(string reason) => new(problemName, instance, reason);
}
