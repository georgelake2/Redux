using System.Numerics;
using API.Interfaces;
using API.Problems.NPComplete.NPC_RSA.Solvers;
using API.Problems.NPComplete.NPC_RSA.Verifiers;
using API.Problems.NPComplete.NPC_RSA.Visualizations;

namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// The RSA problem from an eavesdropper's point of view: given a public key (N, e) and intercepted
/// ciphertext, recover the plaintext.
///
/// An instance comes in two forms:
/// <list type="bullet">
/// <item><c>(N,e,c)</c>: one ciphertext number c. The answer is the number m with m^e = c (mod N).</item>
/// <item><c>(N,e,"TEXT")</c>: message mode. The message is encrypted letter by letter (see
/// <see cref="RSAAlphabet"/>) when the instance is read, and only the ciphertexts are kept, so the
/// attacker, and every solver, sees exactly what an eavesdropper would. The answer is the recovered text.</item>
/// </list>
///
/// The intended receiver decrypts with the private exponent d. An attacker has only the public values, so
/// every solver here is an attack. Checking a proposed answer is just encryption, which places the problem in NP.
/// </summary>
class RSA : IProblem<RSAFactoringAttackSolver, RSAVerifier, RSAKnowledgeTableVisualization> {

    // --- Fields ---
    public string problemName { get; } = "RSA";
    public string problemLink { get; } = "https://en.wikipedia.org/wiki/RSA_problem";
    public string formalDefinition { get; } = "RSA = {<N, e, c> | some m with 0 <= m < N has m^e = c (mod N)}";
    public string problemDefinition { get; } =
        "Recover an RSA-encrypted message using only what an eavesdropper sees: the public key (N, e) " +
        "and the intercepted ciphertext. The intended receiver decrypts with the private exponent d; " +
        "an attacker has to find the message some other way, for example by factoring N to rebuild d.";
    public string inputDescription { get; } =
        "N, the public modulus (a product of two primes p and q); e, the public exponent; and either one " +
        "ciphertext number c or a message in quotes, which is encrypted letter by letter (A = 1 ... Z = 26, space = 27)";
    public string outputDescription { get; } =
        "The plaintext: the number m with 0 <= m < N and m^e = c (mod N), or the recovered message text";
    public string source { get; } =
        "Rivest, R. L., Shamir, A., and Adleman, L. (1978). A Method for Obtaining Digital Signatures and " +
        "Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.";
    public string sourceLink { get; } = "https://doi.org/10.1145/359340.359342";
    // The walkthrough on georgelake.dev, opened on its high-school version (a switch on the page shows the CS one).
    public string walkthroughLink { get; } = "https://georgelake.dev/research/guides/rsa/#hs";
    public string sourceFile { get; } = SourceFile.Path();
    public string wikiName { get; } = "https://en.wikipedia.org/wiki/RSA_(cryptosystem)";
    public string[] contributors { get; } = { "George Lake" };

    public const string InstanceGrammar = "(N,e,c) or (N,e,\"TEXT\")";

    // A message, so a student sees message mode straight away. The Encryption Lesson's worked example is
    // the number form (55,3,52), which decrypts to the lesson's message 13.
    private static readonly string _defaultInstance = "(55,3,\"Hello World\")";
    public string defaultInstance { get; } = _defaultInstance;
    public string instanceFormat { get; } =
        $"Format: {InstanceGrammar}: public modulus N >= 3, public exponent e with 1 < e < N, and either one " +
        $"ciphertext c with 0 <= c < N or a message of letters and spaces in double quotes, which needs " +
        $"N > {RSAAlphabet.LargestCode}. Examples: (55,3,52) and {_defaultInstance}";
    public string certificateFormat { get; } =
        $"Format: {RSAVerifier.CertificateGrammar} Example: {RSAVerifier.CertificateExample}";
    public string instance { get; set; } = string.Empty;

    // Declared, not derived. Recovering m is easy to check (one encryption) and is not known to be
    // NP-complete or in P, the same standing as integer factorization (PRIMEFACTOR).
    public ComplexityClass complexityClass { get; } = ComplexityClass.NP;
    // Declared, not derived. Redux has no cryptography category yet; RSA is modular arithmetic.
    public ProblemType problemType { get; } = ProblemType.AlgebraAndNumberTheory;

    public RSAFactoringAttackSolver defaultSolver { get; } = new RSAFactoringAttackSolver();
    public RSAVerifier defaultVerifier { get; } = new RSAVerifier();
    public RSAKnowledgeTableVisualization defaultVisualization { get; } = new RSAKnowledgeTableVisualization();

    // --- Properties ---

    /// <summary>The public modulus N.</summary>
    public BigInteger modulus { get; }

    /// <summary>The public exponent e.</summary>
    public BigInteger publicExponent { get; }

    /// <summary>
    /// What the attacker intercepted: one number in the (N,e,c) form, or one per letter in message mode.
    /// The message itself is never stored.
    /// </summary>
    public IReadOnlyList<BigInteger> ciphertexts { get; }

    /// <summary>True for an (N,e,"TEXT") instance, whose answer is text rather than a number.</summary>
    public bool isMessage { get; }

    // --- Constructors ---

    public RSA() : this(_defaultInstance) {
    }

    /// <summary>
    /// Reads "(N,e,c)" or "(N,e,"TEXT")". Only the format and the ranges are checked here: whether N really
    /// is a product of two distinct primes is something an attacker finds out, so the solvers report it.
    /// Parsed by hand because the instance parser (SPADE) has no quoted-text type.
    /// </summary>
    public RSA(string instance) {
        this.instance = instance;

        string body = instance.Trim();
        if (body.Length < 2 || body[0] != '(' || body[^1] != ')')
            throw Invalid("expected (N,e,c) or (N,e,\"TEXT\") in parentheses");
        // At most three parts, so any comma inside a message lands in the third one (and is then rejected).
        string[] parts = body[1..^1].Split(',', 3);
        if (parts.Length != 3)
            throw Invalid("expected three values: N, e, and the ciphertext or a quoted message");

        modulus = ParseInteger(parts[0].Trim(), "N");
        publicExponent = ParseInteger(parts[1].Trim(), "e");
        if (modulus < 3)
            throw Invalid($"N must be at least 3, got {modulus}");
        if (publicExponent <= 1 || publicExponent >= modulus)
            throw Invalid($"e must satisfy 1 < e < N, got e = {publicExponent}");

        string third = parts[2].Trim();
        if (third.StartsWith('"')) {
            isMessage = true;
            ciphertexts = EncryptMessage(third);
        } else {
            BigInteger ciphertext = ParseInteger(third, "c");
            if (ciphertext < 0 || ciphertext >= modulus)
                throw Invalid($"c must satisfy 0 <= c < N, got c = {ciphertext}");
            ciphertexts = new[] { ciphertext };
        }
    }

    // --- Methods ---

    /// <summary>
    /// The answer for a full set of recovered plaintexts, one per ciphertext: the number itself, or in
    /// message mode the decoded text ("?" for a code that is not a letter, which a valid key never produces).
    /// </summary>
    public string Answer(IReadOnlyList<BigInteger> plaintexts) =>
        isMessage
            ? new string(plaintexts.Select(m => RSAAlphabet.Decode(m) ?? '?').ToArray())
            : plaintexts[0].ToString();

    /// <summary>Encrypts a quoted message letter by letter, as the sender would.</summary>
    private List<BigInteger> EncryptMessage(string quoted) {
        if (quoted.Length < 2 || !quoted.EndsWith('"'))
            throw Invalid("the message must be enclosed in double quotes");
        string message = quoted[1..^1];
        if (message.Length == 0)
            throw Invalid("the message is empty");
        foreach (char ch in message) {
            if (!RSAAlphabet.IsEncodable(ch))
                throw Invalid($"'{ch}' cannot be encrypted: a message may contain only letters A-Z and spaces");
        }
        if (modulus <= RSAAlphabet.LargestCode)
            throw Invalid($"a message needs N > {RSAAlphabet.LargestCode} so every letter code is below N, got N = {modulus}");

        return message.Select(ch => BigInteger.ModPow(RSAAlphabet.Encode(ch), publicExponent, modulus)).ToList();
    }

    private BigInteger ParseInteger(string text, string name) {
        if (!BigInteger.TryParse(text, out BigInteger value))
            throw Invalid($"{name} must be a whole number, got '{text}'");
        return value;
    }

    private ProblemParseException Invalid(string reason) => new(problemName, instance, reason);
}
