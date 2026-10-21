using System.Numerics;
using API.Interfaces;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Solvers;

/// <summary>
/// The most direct attack on Diffie-Hellman: try every exponent x = 0, 1, 2, ... until g^x mod p equals Alice's
/// public value A. That x is her private key, which gives the shared secret and the message.
/// </summary>
class DHBruteForceDiscreteLogSolver : ISolver<DIFFIEHELLMAN> {

    // --- Fields ---
    public string solverName { get; } = "DH Brute Force Discrete Log";
    public string solverDefinition { get; } =
        "Tries every exponent x = 0, 1, 2, ... in turn, multiplying by g each time, until g^x mod p equals Alice's " +
        "public value A. That x is her private key a; the shared secret is then s = B^a mod p, and each intercepted " +
        "letter is decrypted with m = c x s^-1 mod p. Up to p - 1 tries, which is exponential in the key's bit length.";
    public string source { get; } =
        "Diffie, W., and Hellman, M. E. (1976). New Directions in Cryptography. IEEE Transactions on Information " +
        "Theory, 22(6), 644-654.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. Exhaustive search over every exponent, no pruning.
    public SolverType solverType { get; } = SolverType.BruteForce;
    // Up to p - 1 multiplications: linear in the value of p, exponential in its bit length.
    public SolverComplexityBucket complexityBucket { get; } = SolverComplexityBucket.Exponential;
    public MathematicalFunction timeComplexity { get; } = new("p", " in the value of p (exponential in p's bit length)");

    public const string Timeout = "TIMEOUT";

    // --- Constructors ---
    public DHBruteForceDiscreteLogSolver() { }

    // --- Methods ---

    public string solve(DIFFIEHELLMAN problem) => Attack(problem).Answer;

    public List<object> GetSteps(DIFFIEHELLMAN problem) => Attack(problem).Steps.Cast<object>().ToList();

    /// <summary>
    /// Runs the attack once, returning the answer (or the reason there is none) and one step for each secret
    /// value recovered along the way.
    /// </summary>
    private (string Answer, List<DHStep> Steps) Attack(DIFFIEHELLMAN problem) {
        BigInteger p = problem.modulus, g = problem.generator, target = problem.publicA;
        var steps = new List<DHStep>();

        // Walk through g^0, g^1, g^2, ... one multiplication at a time.
        BigInteger value = 1;
        for (BigInteger x = 0; x <= p - 2; x++) {
            if (timerHasExpired)
                return (Timeout, steps);
            if (value == target) {
                BigInteger tries = x + 1;
                steps.Add(new DHStep(DHStep.A, x.ToString(),
                    $"Tried x = 0, 1, 2, ... : {g}^{x} mod {p} = {target} = A after {tries} {(tries == 1 ? "try" : "tries")}"));
                return (DHKeyRecovery.FinishFromPrivateKey(problem, x, steps), steps);
            }
            value = value * g % p;
        }
        return ($"No solution: A = {target} is not a power of g = {g} mod p = {p}", steps);
    }
}
