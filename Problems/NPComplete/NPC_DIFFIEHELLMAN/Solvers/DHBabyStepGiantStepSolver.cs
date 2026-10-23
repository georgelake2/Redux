using System.Numerics;
using API.Interfaces;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Solvers;

/// <summary>
/// Shanks' baby-step giant-step attack: write the unknown key as a = i x m + j with m = ceil(sqrt(p - 1)), store
/// the m "baby steps" g^j, then take "giant steps" A x g^(-m i) until one lands on a stored baby step. About
/// 2 sqrt(p) multiplications instead of p: much faster than brute force, yet still exponential in the key's bit
/// length, which is why Shor's quantum algorithm matters.
/// </summary>
class DHBabyStepGiantStepSolver : ISolver<DIFFIEHELLMAN> {

    // --- Fields ---
    public string solverName { get; } = "DH Baby-Step Giant-Step";
    public string solverDefinition { get; } =
        "Shanks' algorithm. With m = ceil(sqrt(p - 1)), it stores the baby steps g^j for j = 0 ... m - 1, then takes " +
        "giant steps A x g^(-m i) for i = 0, 1, 2, ... until one equals a stored baby step g^j; then Alice's key is " +
        "a = i x m + j. About 2 sqrt(p) multiplications and sqrt(p) memory instead of p tries, but still exponential " +
        "in the key's bit length. The shared secret and message follow as for the brute-force attack.";
    public string source { get; } =
        "Shanks, D. (1971). Class number, a theory of factorization, and genera. Proceedings of Symposia in Pure " +
        "Mathematics, 20, 415-440.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. A time-memory trade-off that is still an exhaustive search, just meet-in-the-middle.
    public SolverType solverType { get; } = SolverType.BruteForce;
    // About 2 sqrt(p) multiplications: polynomial in the value of p, exponential in its bit length.
    public SolverComplexityBucket complexityBucket { get; } = SolverComplexityBucket.Exponential;
    public MathematicalFunction timeComplexity { get; } = new("sqrt(p)", " in the value of p (exponential in p's bit length)");

    public const string Timeout = "TIMEOUT";

    // --- Constructors ---
    public DHBabyStepGiantStepSolver() { }

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
        BigInteger m = CeilingSqrt(p - 1);

        // Baby steps: remember the first j that gives each value g^j, for j = 0 ... m - 1.
        var babySteps = new Dictionary<BigInteger, BigInteger>();
        BigInteger value = 1;
        for (BigInteger j = 0; j < m; j++) {
            if (timerHasExpired)
                return (Timeout, steps);
            babySteps.TryAdd(value, j);
            value = value * g % p;
        }

        // Giant steps: A, A g^-m, A g^-2m, ... ; the first match gives the smallest key.
        BigInteger? gInverse = DHKeyRecovery.ModularInverse(g, p);
        if (gInverse is not BigInteger inverse)
            return ($"No solution: g = {g} has no inverse mod p = {p} (p is not prime)", steps);
        BigInteger giantFactor = BigInteger.ModPow(inverse, m, p);
        BigInteger gamma = target;
        for (BigInteger i = 0; i < m; i++) {
            if (timerHasExpired)
                return (Timeout, steps);
            if (babySteps.TryGetValue(gamma, out BigInteger j)) {
                BigInteger key = i * m + j;
                BigInteger multiplications = m + i + 1;
                steps.Add(new DHStep(DHStep.A, key.ToString(),
                    $"Giant step {i} matched baby step {j}, so a = {i} × {m} + {j} = {key} ({multiplications} multiplications)"));
                return (DHKeyRecovery.FinishFromPrivateKey(problem, key, steps), steps);
            }
            gamma = gamma * giantFactor % p;
        }
        return ($"No solution: A = {target} is not a power of g = {g} mod p = {p}", steps);
    }

    /// <summary>The smallest m with m x m >= n, for n >= 0.</summary>
    private static BigInteger CeilingSqrt(BigInteger n) {
        if (n <= 1)
            return 1;
        // Newton's method from an estimate above the root, then nudge to the exact ceiling.
        BigInteger x = BigInteger.One << (int)((n.GetBitLength() + 1) / 2);
        while (true) {
            BigInteger next = (x + n / x) / 2;
            if (next >= x)
                break;
            x = next;
        }
        while (x * x < n)
            x++;
        while ((x - 1) * (x - 1) >= n)
            x--;
        return x;
    }
}
