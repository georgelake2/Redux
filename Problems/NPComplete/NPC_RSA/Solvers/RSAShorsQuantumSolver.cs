using System.Numerics;
using System.Text.Json;
using API.Interfaces;
using API.Interfaces.Steps;
using API.Tools;

namespace API.Problems.NPComplete.NPC_RSA.Solvers;

/// <summary>
/// The quantum attack on RSA: factor N with Shor's algorithm, then rebuild the private key and decrypt exactly as
/// the classical factoring attack does. The factoring itself runs in Redux's quantum service (quantumsolver), the
/// same endpoint PRIMEFACTOR's Shor's solver uses, on a simulated quantum computer; everything after p and q is
/// shared with the factoring attack (RSAKeyRecovery), so the two runs differ only in how p and q were found.
/// </summary>
class RSAShorsQuantumSolver : ISolver<RSA, Assignment> {

    // --- Fields ---
    public string solverName { get; } = "RSA Shor's Algorithm";
    public string solverDefinition { get; } =
        "Sends the public modulus N to Redux's quantum service, which factors it with Shor's algorithm on a " +
        "simulated quantum computer (Qiskit Aer): quantum phase estimation finds the period r of a^x mod N for a " +
        "random base a, and gcd(a^(r/2) - 1, N) splits N into p and q. The rest is the same as the factoring " +
        "attack: phi = (p - 1)(q - 1), d = e^-1 mod phi, and m = c^d mod N for each ciphertext. On a real quantum " +
        "computer the factoring takes time polynomial in N's bit length, where trial division is exponential. " +
        "Simplification: for these toy sizes the controlled multiplications by a^(2^i) mod N are permutation " +
        "gates computed classically, not general quantum arithmetic circuits. The simulator handles N below 128: each extra bit " +
        "adds three qubits, and keys over 7 bits take minutes.";
    public string source { get; } =
        "Shor, P. W. (1997). Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a " +
        "Quantum Computer. SIAM Journal on Computing, 26(5), 1484-1509.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public bool timerHasExpired { get; set; }

    // Declared, not derived. complexityBucket is left Unclassified on purpose, as for PRIMEFACTOR's
    // ShorsQuantumSolver: a classical growth bucket would misdescribe a quantum algorithm whose point is
    // the quantum-vs-classical separation.
    public SolverType solverType { get; } = SolverType.Quantum;
    // Shor's period finding plus the classical post-processing: polynomial in N's bit length, the textbook
    // O((log N)^3), against the sqrt(N) divisions of trial division.
    public MathematicalFunction timeComplexity { get; } = new("(log N)^3", " in the bit length of N, on a quantum computer");

    public const string Timeout = "TIMEOUT";

    /// <summary>The quantum service's factoring endpoint, shared with PRIMEFACTOR's ShorsQuantumSolver.</summary>
    public const string Endpoint = "/prime-factorization-quantum";

    /// <summary>
    /// The largest N is 127 (7 bits). The quantum service accepts N under 10 bits, but its simulation grows steeply: on a
    /// 2-CPU machine 7-bit moduli took from 2 to 25 seconds and 8-bit ones did not finish in 5 minutes (2026-11-20).
    /// </summary>
    public const int ModulusLimit = 128;

    /// <summary>The quantum service's own time limit for one run (SOLVER_TIMEOUT_SECONDS in its routes.py).</summary>
    public const int ServiceTimeoutSeconds = 60;

    /// <summary>
    /// Sends the request body (N as text) to the quantum service and returns its JSON reply. Tests replace it with
    /// a fake service, so they never touch the global quantum-service settings other tests rely on.
    /// </summary>
    internal Func<string, string> CallService { get; set; } =
        body => new QuantumServerAPI().PostRawJsonAsync(Endpoint, body).GetAwaiter().GetResult();

    // --- Constructors ---
    public RSAShorsQuantumSolver() { }

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
    /// Runs the attack once, returning the answer (the plaintext, or the reason there is none) together with one step
    /// for each secret value recovered along the way.
    /// </summary>
    private (string Answer, List<RSAStep> Steps) Attack(RSA problem) {
        BigInteger n = problem.modulus;
        var steps = new List<RSAStep>();

        if (n >= ModulusLimit)
            return ($"{RecoveredValues.NotRun} the simulated Shor's solver handles N below {ModulusLimit} (7 bits), and N = {n}; " +
                "larger keys take minutes on the simulator", steps);
        if (timerHasExpired)
            return (Timeout, steps);

        // 1. Shor's algorithm, in the quantum service.
        var (factors, failure) = AskForFactors(n);
        if (timerHasExpired)
            return (Timeout, steps);
        if (failure is not null)
            return (failure, steps);

        // The service returns N's prime factors in increasing order. An RSA modulus has exactly two, and they differ.
        string found = string.Join(" × ", factors);
        if (factors.Aggregate(BigInteger.One, (product, f) => product * f) != n)
            return ($"{RecoveredValues.NotRun} the quantum service's factors {found} do not multiply to N = {n}", steps);
        if (factors.Count == 1) {
            return IsPrime(n)
                ? ($"No solution: N = {n} is prime, so it is not an RSA modulus", steps)
                : ($"{RecoveredValues.NotRun} Shor's algorithm did not split N = {n} on this run; run it again", steps);
        }
        if (factors.Count != 2 || factors[0] == factors[1] || !IsPrime(factors[0]) || !IsPrime(factors[1]))
            return ($"No solution: N = {n} is not a product of two distinct primes (Shor's algorithm found {found})", steps);

        BigInteger p = factors[0], q = factors[1];
        steps.Add(new RSAStep(RSAStep.P, p.ToString(), p == 2
            ? $"N = {n} is even, so p = 2 (the quantum service checks this before running Shor's algorithm)"
            : $"Shor's algorithm on a quantum simulator split {n} into {p} × {q} (quantum period finding)"));

        // 2. The other factor.
        steps.Add(new RSAStep(RSAStep.Q, q.ToString(), $"q = N / p = {n} / {p}"));

        // 3 to 5. Rebuild the private key and decrypt, exactly as the factoring attack does.
        return (RSAKeyRecovery.Finish(problem, p, q, steps), steps);
    }

    /// <summary>
    /// Asks the quantum service to factor N. Returns the factors in increasing order, or a message saying why there
    /// are none: the service is unreachable or too slow, or it answered with a message (such as its own timeout).
    /// </summary>
    private (List<BigInteger> Factors, string? Failure) AskForFactors(BigInteger n) {
        string reply;
        try {
            reply = CallService(n.ToString());
        } catch (TimeoutException) {
            return (new(), $"{RecoveredValues.NotRun} the quantum service did not answer within {QuantumServerAPI.RequestTimeoutSeconds} seconds");
        } catch (HttpRequestException ex) {
            return (new(), $"{RecoveredValues.NotRun} could not reach the quantum service ({ex.Message})");
        } catch (Exception ex) {
            // For example, quantum-service settings that were never configured.
            return (new(), $"{RecoveredValues.NotRun} could not call the quantum service ({ex.GetType().Name})");
        }

        try {
            using JsonDocument doc = JsonDocument.Parse(reply);
            if (!doc.RootElement.TryGetProperty("answer", out JsonElement answer))
                return (new(), $"{RecoveredValues.NotRun} the quantum service's reply has no answer");
            if (answer.ValueKind == JsonValueKind.String) {
                string message = answer.GetString() ?? string.Empty;
                return (new(), message == "timeout"
                    ? $"{RecoveredValues.NotRun} the quantum simulator gave up after {ServiceTimeoutSeconds} seconds; a smaller N runs faster"
                    : $"{RecoveredValues.NotRun} the quantum service replied \"{message}\"");
            }
            if (answer.ValueKind != JsonValueKind.Array)
                return (new(), $"{RecoveredValues.NotRun} the quantum service's answer is not a list of factors");
            var factors = answer.EnumerateArray().Select(f => BigInteger.Parse(f.GetRawText())).Order().ToList();
            if (factors.Count == 0)
                return (new(), $"{RecoveredValues.NotRun} the quantum service returned no factors");
            return (factors, null);
        } catch (Exception ex) when (ex is JsonException or FormatException) {
            return (new(), $"{RecoveredValues.NotRun} the quantum service's reply could not be read");
        }
    }

    /// <summary>Primality by trial division, used to check the service's factors; N is below 128, so this is instant.</summary>
    private static bool IsPrime(BigInteger value) {
        if (value < 2)
            return false;
        for (BigInteger divisor = 2; divisor * divisor <= value; divisor++) {
            if (value % divisor == 0)
                return false;
        }
        return true;
    }
}
