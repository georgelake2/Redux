using System.Numerics;
using System.Text.Json;
using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_RSA.Solvers;
using API.Tools;

namespace API.Problems.NPComplete.NPC_RSA.Visualizations;

/// <summary>
/// Shor's period-finding circuit for the RSA modulus N, the one the quantum service ran: Hadamards on the 2n counting
/// qubits, one controlled multiply by a^(2^j) mod N per counting qubit on the n-qubit work register, the inverse QFT
/// and the measurement. The work register is drawn as one wire.
///
/// Before a run it shows the circuit's shape for N with the multipliers written as powers of a. After a run of the
/// RSA Shor's solver it steps through the circuit of the attempt that split N (or, if that base needed no circuit,
/// the last one that did), one column per step, with the real multipliers and the measured x.
/// </summary>
class RSAShorsCircuitVisualization : IVisualization<RSA, API_QUANTUMCIRCUIT> {

    // --- Fields ---
    public string visualizationName { get; } = "RSA Shor's Algorithm Circuit";
    public string visualizationDefinition { get; } =
        "The quantum circuit Shor's algorithm runs to find the period r of a^x mod N: Hadamards put the counting " +
        "qubits into every value at once, controlled multiplies by a^(2^j) mod N write a^x mod N into the work " +
        "register, the inverse quantum Fourier transform turns the repeat into peaks, and one measurement gives x. " +
        "Run it with the RSA Shor's Algorithm solver to step through the circuit of the attempt that split N.";
    public string source { get; } =
        "Shor, P. W. (1997). Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a " +
        "Quantum Computer. SIAM Journal on Computing, 26(5), 1484-1509.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.QuantumCircuitD3;
    // The solver a picture uses when none is named, which is how Redux_Frontend draws the picture before a Run.
    // The instant classical attack keeps that from calling the quantum service on every page load; it records no
    // Shor's run, so the picture before a Run is visualize(). Pick the RSA Shor's Algorithm solver to fill it in.
    public ISolver solver { get; } = new RSAFactoringAttackSolver();
    // Reads the service's record from the RSA Shor's solver's Done step (see ShorsRun).
    Type? IVisualization.StepShape => typeof(Assignment);

    private const string Work = "work";
    private const string Bus = "x";

    // --- Constructors ---
    public RSAShorsCircuitVisualization() { }

    // --- Methods ---

    /// <summary>The circuit's shape for N, before any run: the multipliers are written as powers of a.</summary>
    public API_QUANTUMCIRCUIT visualize(RSA problem) {
        int t = CountingQubits(problem.modulus);
        var labels = GenericLabels(t);
        string caption = problem.modulus >= RSAShorsQuantumSolver.ModulusLimit
            ? $"N = {problem.modulus} needs {t} counting qubits and {t / 2} work qubits; the simulated solver runs N below {RSAShorsQuantumSolver.ModulusLimit}."
            : $"N = {problem.modulus} takes {t / 2} bits: {t} counting qubits (c0 to c{t - 1}) and {t / 2} work qubits (one wire). " +
              "Run the RSA Shor's Algorithm solver to see the circuit it ran.";
        return Circuit(problem.modulus, t, labels, t + 3, caption);
    }

    /// <summary>One frame per column of the circuit the run used, each adding that column's gates.</summary>
    public List<API_JSON> StepsVisualization(RSA problem, List<object> steps) {
        ShorsRun? run = ShorsRun.FromSteps(steps);
        var frames = new List<API_JSON>();
        if (run is null)
            return frames;

        ShorsAttempt? shown = run.Winner is { Circuit: true } ? run.Winner : run.LastCircuit;
        if (shown is null) {
            string why = run.Classical switch {
                "even" => $"N = {run.N} is even, so p = 2 without any circuit.",
                "perfect_power" => $"N = {run.N} is a power of one prime, split without any circuit.",
                "prime" => $"N = {run.N} is prime, so there is nothing to split.",
                _ => run.Winner is { } lucky
                    ? $"The first base, a = {lucky.A}, already shares a factor with N: gcd({lucky.A}, {run.N}) = {lucky.Gcd}. No circuit was needed."
                    : "The quantum service ran no circuit.",
            };
            int width = CountingQubits(problem.modulus);
            frames.Add(Circuit(problem.modulus, width, GenericLabels(width), width + 3, why));
            return frames;
        }

        int t = run.CountingQubits;
        var labels = shown.Multipliers!.Select(v => $"×{v}").ToArray();
        int attempt = run.Attempts.IndexOf(shown) + 1;
        string who = $"Attempt {attempt}, a = {shown.A}";
        for (int stage = 1; stage <= t + 3; stage++) {
            string caption = stage switch {
                1 => $"{who}. Superpose: one H on each of the {t} counting qubits makes them hold every number from 0 to {(1L << t) - 1} at once; X sets the work register to 1.",
                _ when stage <= t + 1 => MultiplyCaption(who, run.N, shown, stage - 2),
                _ when stage == t + 2 => $"{who}. Inverse QFT: turns the repeat hidden in the multiplies (period r) into peaks, so one measurement lands near a multiple of 2^{t} ÷ r.",
                _ => $"{who}. Measure: the counting qubits give x = {shown.X} (binary {Convert.ToString(shown.X ?? 0, 2).PadLeft(t, '0')}). {Outcome(run.N, shown)}",
            };
            frames.Add(Circuit(problem.modulus, t, labels, stage, caption));
        }
        return frames;
    }

    private static string MultiplyCaption(string who, int n, ShorsAttempt shown, int j) {
        int v = shown.Multipliers![j];
        string what = v == 1
            ? "multiplying by 1 changes nothing, so this gate could be left out"
            : $"when c{j} is 1 it replaces the work value y with y × {v} mod {n}";
        return $"{who}. Controlled ×{v} on c{j}: {v} = {shown.A}^{1L << j} mod {n}, and {what}.";
    }

    private static string Outcome(int n, ShorsAttempt shown) =>
        shown.Succeeded
            ? $"It gives r = {shown.R} and {n} = {shown.Factors![0]} × {shown.Factors[1]}; see the decoding table for how."
            : $"This attempt failed: {shown.Result(n)}.";

    internal static int CountingQubits(BigInteger n) => 2 * (int)n.GetBitLength();

    /// <summary>Box labels before a run, when a is not known yet: ×a, ×a^2, ×a^4, ...</summary>
    private static string[] GenericLabels(int t) =>
        Enumerable.Range(0, t).Select(j => j == 0 ? "×a" : $"×a^{1L << j}").ToArray();

    /// <summary>
    /// The circuit with every gate up to column <paramref name="columns"/> (1 = the Hadamards; t + 3 = everything).
    /// <paramref name="multipliers"/> are the box labels on the work wire, one per counting qubit.
    /// </summary>
    private static API_QUANTUMCIRCUIT Circuit(BigInteger n, int t, string[] multipliers, int columns, string caption) {
        var counting = Enumerable.Range(0, t).Select(j => $"c{j}").ToArray();
        var gates = new List<QasmD3GateOp>();
        void Add(int time, string id, string type, string[] targets, string? label = null, string[]? classical = null) {
            if (time < columns)
                gates.Add(new QasmD3GateOp { id = id, type = type, targets = targets, label = label, classical = classical, time = time });
        }

        Add(0, "x-work", "x", new[] { Work });
        foreach (string c in counting)
            Add(0, $"h-{c}", "h", new[] { c });
        for (int j = 0; j < t; j++)
            Add(1 + j, $"mul-{j}", "multiply", new[] { counting[j], Work }, label: multipliers[j]);
        foreach (string c in counting)
            Add(t + 1, $"iqft-{c}", "iqft", new[] { c }, label: "QFT†");
        foreach (string c in counting)
            Add(t + 2, $"m-{c}", "m", new[] { c }, classical: new[] { Bus });

        var all = counting.Append(Work).ToArray();
        var payload = new QasmD3Payload {
            qubits = all,
            classical = new[] { Bus },
            gates = gates,
            overlays = new List<QasmD3Overlay> {
                new() { id = "superpose", label = "Superpose", timeStart = 0, timeEnd = 0, targets = all },
                new() { id = "modexp", label = "Modular exponentiation", timeStart = 1, timeEnd = t, targets = all },
                new() { id = "iqft", label = "Inverse QFT", timeStart = t + 1, timeEnd = t + 1, targets = counting },
                new() { id = "measure", label = "Measure", timeStart = t + 2, timeEnd = t + 2, targets = counting },
            },
            metadata = new Dictionary<string, object?> {
                ["caption"] = caption,
                // A picture of the circuit the quantum service runs, not an instance to build: Redux_Frontend
                // turns off its drag-and-drop circuit editing for it.
                ["readOnly"] = true,
                // Every column the full circuit uses, so stepping through it keeps the diagram's width.
                ["layoutTimes"] = Enumerable.Range(0, t + 3).ToArray(),
                // Redux_Frontend's Shor's explorer page, which has the parts this picture can't draw.
                ["link"] = new Dictionary<string, string> {
                    ["label"] = "Explore this circuit gate by gate",
                    ["href"] = $"/learn/shor?N={n}",
                },
            },
        };

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(payload));
        return new API_QUANTUMCIRCUIT {
            format = QuantumCircuitFormat.D3,
            d3 = doc.RootElement.Clone(),
            metadata = new Dictionary<string, object?> { ["caption"] = caption },
        };
    }
}
