using System.Numerics;
using API.Interfaces;

namespace API.Problems.NPComplete.NPC_RSA.Solvers;

/// <summary>
/// The most direct attack on RSA: encrypt every possible message with the public key until one matches the
/// ciphertext. It never learns p, q, phi or d; it just tries up to N messages per ciphertext, which is why
/// real RSA is safe from it and why the factoring attack is the one worth studying.
/// </summary>
class RSAPlaintextSearchSolver : ISolver<RSA> {

    // --- Fields ---
    public string solverName { get; } = "RSA Brute Force Plaintext Search";
    public string solverDefinition { get; } =
        "For each ciphertext, tries every message m = 0, 1, 2, ... in turn, encrypting each with the public " +
        "key, until m^e mod N equals the ciphertext. It needs no knowledge of the private key, but up to N " +
        "encryptions per ciphertext, which is exponential in the key's bit length.";
    public string source { get; } =
        "Rivest, R. L., Shamir, A., and Adleman, L. (1978). A Method for Obtaining Digital Signatures and " +
        "Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. Exhaustive search over every possible message, no pruning.
    public SolverType solverType { get; } = SolverType.BruteForce;
    // Up to N encryptions: linear in the value of N, exponential in its bit length.
    public SolverComplexityBucket complexityBucket { get; } = SolverComplexityBucket.Exponential;
    public MathematicalFunction timeComplexity { get; } = new("N", " encryptions per ciphertext, in the value of N (exponential in N's bit length)");

    public const string Timeout = "TIMEOUT";

    // --- Constructors ---
    public RSAPlaintextSearchSolver() { }

    // --- Methods ---

    public string solve(RSA problem) => Search(problem).Answer;

    public List<object> GetSteps(RSA problem) => Search(problem).Steps.Cast<object>().ToList();

    /// <summary>
    /// Runs the search once, returning the answer (the plaintext, or the reason there is none) and one step
    /// per ciphertext. A ciphertext seen before is the same letter again, so it costs no new search: the
    /// weakness of encrypting a message letter by letter.
    /// </summary>
    private (string Answer, List<RSAStep> Steps) Search(RSA problem) {
        BigInteger n = problem.modulus, e = problem.publicExponent;
        var steps = new List<RSAStep>();
        var plaintexts = new List<BigInteger>();
        var seen = new Dictionary<BigInteger, (BigInteger Plaintext, int Letter)>();

        for (int i = 0; i < problem.ciphertexts.Count; i++) {
            BigInteger c = problem.ciphertexts[i];

            if (seen.TryGetValue(c, out var earlier)) {
                plaintexts.Add(earlier.Plaintext);
                steps.Add(new RSAStep(RSAStep.M, earlier.Plaintext.ToString(),
                    $"Letter {i + 1}: ciphertext {c} already appeared as letter {earlier.Letter + 1}, " +
                    $"so it is {LetterName(earlier.Plaintext)} again (no search needed)", i));
                continue;
            }

            BigInteger? found = null, tries = 0;
            for (BigInteger m = 0; m < n; m++) {
                if (timerHasExpired)
                    return (Timeout, steps);
                tries++;
                if (BigInteger.ModPow(m, e, n) == c) {
                    found = m;
                    break;
                }
            }
            if (found is not BigInteger plaintext)
                return ($"No solution: no m with 0 <= m < {n} has m^{e} mod {n} = {c}", steps);

            plaintexts.Add(plaintext);
            seen[c] = (plaintext, i);
            string search = $"Tried m = 0, 1, 2, ... : {plaintext}^{e} mod {n} = {c} after {tries} {(tries == 1 ? "try" : "tries")}";
            steps.Add(problem.isMessage
                ? new RSAStep(RSAStep.M, plaintext.ToString(), $"Letter {i + 1}: {search}, which is {LetterName(plaintext)}", i)
                : new RSAStep(RSAStep.M, plaintext.ToString(), search));
        }
        return (problem.Answer(plaintexts), steps);
    }

    private static string LetterName(BigInteger code) =>
        RSAAlphabet.Decode(code) is char letter ? RSAAlphabet.Describe(letter) : "not a letter code";
}
