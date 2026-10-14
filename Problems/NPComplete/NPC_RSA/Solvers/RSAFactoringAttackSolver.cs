using System.Numerics;
using API.Interfaces;

namespace API.Problems.NPComplete.NPC_RSA.Solvers;

/// <summary>
/// The classical attack on RSA: factor N by trial division, then rebuild the private key exactly the way
/// its owner made it (phi, then d), and decrypt. Each value it recovers is one recorded step, so the run
/// doubles as a walkthrough of RSA key generation and decryption seen from the attacker's side.
/// </summary>
class RSAFactoringAttackSolver : ISolver<RSA> {

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

    public string solve(RSA problem) => Attack(problem).Answer;

    public List<object> GetSteps(RSA problem) => Attack(problem).Steps.Cast<object>().ToList();

    /// <summary>
    /// Runs the attack once, returning the answer (the plaintext, or the reason there is none) together
    /// with one step for each secret value recovered along the way.
    /// </summary>
    private (string Answer, List<RSAStep> Steps) Attack(RSA problem) {
        BigInteger n = problem.modulus, e = problem.publicExponent;
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

        // 3. Euler's totient, which only someone who knows p and q can compute.
        BigInteger phi = (p - 1) * (q - 1);
        steps.Add(new RSAStep(RSAStep.Phi, phi.ToString(), $"φ = (p - 1)(q - 1) = {p - 1} × {q - 1}"));

        // 4. The private exponent: the inverse of e modulo phi.
        BigInteger? inverse = ModularInverse(e, phi);
        if (inverse is not BigInteger d)
            return ($"No solution: e = {e} has no inverse mod φ = {phi}, so there is no private key", steps);
        steps.Add(new RSAStep(RSAStep.D, d.ToString(),
            $"Extended Euclid: d = e⁻¹ mod φ, since {e} × {d} = {e * d} ≡ 1 (mod {phi})"));

        // 5. Decrypt every ciphertext with the recovered key, one step each.
        var plaintexts = new List<BigInteger>();
        for (int i = 0; i < problem.ciphertexts.Count; i++) {
            BigInteger c = problem.ciphertexts[i];
            BigInteger m = BigInteger.ModPow(c, d, n);
            plaintexts.Add(m);
            steps.Add(problem.isMessage
                ? new RSAStep(RSAStep.M, m.ToString(),
                    $"Decrypt letter {i + 1}: {c}^{d} mod {n} = {m}, which is {LetterName(m)}", i)
                : new RSAStep(RSAStep.M, m.ToString(), $"Decrypt: m = c^d mod N = {c}^{d} mod {n}"));
        }
        return (problem.Answer(plaintexts), steps);
    }

    private static string LetterName(BigInteger code) =>
        RSAAlphabet.Decode(code) is char letter ? RSAAlphabet.Describe(letter) : "not a letter code";

    /// <summary>The inverse of a modulo m by the extended Euclidean algorithm, or null if gcd(a, m) != 1.</summary>
    private static BigInteger? ModularInverse(BigInteger a, BigInteger m) {
        // Invariant: oldR = oldS * a (mod m) and r = s * a (mod m).
        BigInteger oldR = a % m, r = m, oldS = 1, s = 0;
        while (r != 0) {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
        }
        if (oldR != 1)
            return null;
        return ((oldS % m) + m) % m;
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
