using System.Numerics;
using API.Interfaces;
using API.Interfaces.Steps;

namespace API.Problems.NPComplete.NPC_RSA.Solvers;

/// <summary>
/// The classical attack on RSA: factor N by trial division, then rebuild the private key exactly the way
/// its owner made it (phi, then d), and decrypt. Each value it recovers is one recorded step, so the run
/// doubles as a walkthrough of RSA key generation and decryption seen from the attacker's side.
/// </summary>
class RSAFactoringAttackSolver : ISolver<RSA, Assignment> {

    // --- Fields ---
    public string solverName { get; } = "RSA Factoring Attack";
    public string solverDefinition { get; } =
        "Factors the public modulus N by trial division to find the secret primes p and q, computes " +
        "phi = (p - 1)(q - 1), recovers the private exponent d = e^-1 mod phi with the extended Euclidean " +
        "algorithm, and decrypts each ciphertext with m = c^d mod N. Trial division takes up to sqrt(N) " +
        "divisions, which is exponential in the key's bit length; this is the step Shor's algorithm replaces.";
    public string source { get; } =
        "Rivest, R. L., Shamir, A., and Adleman, L. (1978). A Method for Obtaining Digital Signatures and " +
        "Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. Unpruned trial division dominates the run time.
    public SolverType solverType { get; } = SolverType.BruteForce;
    // Up to sqrt(N) divisions: polynomial in the value of N, exponential in its bit length.
    public SolverComplexityBucket complexityBucket { get; } = SolverComplexityBucket.Exponential;
    public MathematicalFunction timeComplexity { get; } = new("sqrt(N)", " in the value of N (exponential in N's bit length)");

    public const string Timeout = "TIMEOUT";

    // --- Constructors ---
    public RSAFactoringAttackSolver() { }

    // --- Methods ---

    public string solve(RSA problem) => Solve(problem, StepRecorder<Assignment>.Off);

    /// <summary>Runs the attack once and records a step for each value it recovers (see RecoveredValues).</summary>
    public string Solve(RSA problem, StepRecorder<Assignment> rec) {
        SolveProbe.Hit(GetType());
        var (answer, steps) = Attack(problem);
        RecoveredValues.Record(rec, steps.Select(s => (s.Name, s.Value, s.HowFound)).ToList(), answer, Timeout);
        return answer;
    }

    /// <summary>
    /// Runs the attack once, returning the answer (the plaintext, or the reason there is none) together
    /// with one step for each secret value recovered along the way.
    /// </summary>
    private (string Answer, List<RSAStep> Steps) Attack(RSA problem) {
        BigInteger n = problem.modulus;
        var steps = new List<RSAStep>();

        // 1. Trial division: the smallest divisor of N is p.
        BigInteger p = 0, tries = 0;
        for (BigInteger candidate = 2; candidate * candidate <= n; candidate++) {
            if (timerHasExpired)
                return (Timeout, steps);
            tries++;
            if (n % candidate == 0) {
                p = candidate;
                break;
            }
        }
        if (p == 0)
            return ($"No solution: N = {n} is prime, so it is not an RSA modulus", steps);
        steps.Add(new RSAStep(RSAStep.P, p.ToString(),
            $"Trial division: {p} is the first number from 2 up that divides {n} ({tries} {(tries == 1 ? "try" : "tries")})"));

        // 2. The other factor. A real RSA modulus is the product of exactly two distinct primes.
        BigInteger q = n / p;
        bool qIsPrime = IsPrime(q);
        if (timerHasExpired)
            return (Timeout, steps);
        if (q == p || !qIsPrime)
            return ($"No solution: N = {n} is not a product of two distinct primes", steps);
        steps.Add(new RSAStep(RSAStep.Q, q.ToString(), $"q = N / p = {n} / {p}"));

        // 3 to 5. Rebuild the private key and decrypt, as every factoring-based attack does.
        return (RSAKeyRecovery.Finish(problem, p, q, steps), steps);
    }

    /// <summary>Primality by trial division; only called on the cofactor q, after p has been found.</summary>
    private bool IsPrime(BigInteger value) {
        if (value < 2)
            return false;
        for (BigInteger divisor = 2; divisor * divisor <= value; divisor++) {
            if (timerHasExpired || value % divisor == 0)
                return false;
        }
        return true;
    }
}
