using API.Interfaces;

namespace API.Problems.NPComplete.NPC_AES.Solvers;

/// <summary>
/// The only known attack on AES: try every value of the missing key bits, 0, 1, 2, ..., until a candidate key
/// fits. In Eve's view a key fits when it encrypts the known plaintext to the ciphertext; in message mode, when it
/// decrypts the ciphertext to readable text. This 2^k search is the baseline Grover's algorithm is measured
/// against: it needs only about (pi/4) x 2^(k/2) tries.
/// </summary>
class AESBruteForceKeySearchSolver : ISolver<AES> {

    // --- Fields ---
    public string solverName { get; } = "AES Brute Force Key Search";
    public string solverDefinition { get; } =
        "Tries every value of the k missing key bits in turn, 0, 1, 2, ..., each time completing the key with the " +
        "known bits and running AES. In Eve's view a candidate fits when it encrypts the known plaintext to the " +
        "intercepted ciphertext; for a message, when it decrypts the ciphertext to letters and spaces with valid " +
        "padding. Up to 2^k tries, since AES has no shortcut that rules keys out without trying them.";
    public string source { get; } =
        "National Institute of Standards and Technology (2001, updated 2023). Advanced Encryption Standard (AES). " +
        "FIPS PUB 197.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. Exhaustive search over every candidate key, no pruning.
    public SolverType solverType { get; } = SolverType.BruteForce;
    // Up to 2^k AES runs: exponential in the number of unknown key bits.
    public SolverComplexityBucket complexityBucket { get; } = SolverComplexityBucket.Exponential;
    public MathematicalFunction timeComplexity { get; } = new("2^k", " AES runs, for k unknown key bits");

    public const string Timeout = "TIMEOUT";

    // --- Constructors ---
    public AESBruteForceKeySearchSolver() { }

    // --- Methods ---

    public string solve(AES problem) => Attack(problem).Answer;

    public List<object> GetSteps(AES problem) => Attack(problem).Steps.Cast<object>().ToList();

    /// <summary>
    /// Runs the attack once, returning the answer (or the reason there is none) and one step for each secret
    /// value recovered: the missing bits, the full key and, in message mode, the message.
    /// </summary>
    private (string Answer, List<AESStep> Steps) Attack(AES problem) {
        var steps = new List<AESStep>();
        for (long candidate = 0; candidate < problem.candidateCount; candidate++) {
            if (timerHasExpired)
                return (Timeout, steps);
            byte[] key = problem.CandidateKey(candidate);
            string? message = null;
            bool fits = problem.isMessage
                ? (message = AESMessage.Read(AESCipher.Decrypt(problem.ciphertext, key))) is not null
                : AESCipher.Encrypt(problem.knownPlaintext!, key).SequenceEqual(problem.ciphertext);
            if (!fits)
                continue;

            string test = problem.isMessage
                ? "decrypted to letters and spaces with valid padding"
                : "encrypted the known plaintext to the ciphertext";
            steps.Add(new AESStep(AESStep.Bits, problem.MissingBitsText(candidate),
                $"Counted up from 0: on try {candidate + 1} of {problem.candidateCount}, it {test}"));
            steps.Add(new AESStep(AESStep.Key, AES.Hex(key),
                $"The {AESCipher.KeySize * 8 - problem.unknownBits} known bits followed by the {problem.unknownBits} found bits"));
            if (problem.isMessage) {
                steps.Add(new AESStep(AESStep.M, $"\"{message}\"",
                    $"Decrypt the ciphertext with the key and remove the {AESCipher.BlockSize - message!.Length} padding bytes"));
            }
            return (problem.Answer(key, message), steps);
        }
        string reason = problem.isMessage
            ? "decrypts the ciphertext to a message of letters and spaces"
            : "encrypts the plaintext to the ciphertext";
        return ($"No solution: no key with the known bits {reason} (all {problem.candidateCount} tried)", steps);
    }
}
