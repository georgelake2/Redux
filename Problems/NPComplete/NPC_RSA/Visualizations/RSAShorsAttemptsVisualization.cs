using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_RSA.Solvers;

namespace API.Problems.NPComplete.NPC_RSA.Visualizations;

/// <summary>
/// Shor's algorithm's attempts, one row per random base a: the gcd check, whether the circuit ran, the measured x, the
/// period r and how the attempt ended. Shor's algorithm is randomized: a base can fail (x = 0, an odd period, or
/// a^(r/2) = -1 mod N) and the algorithm starts over, so this is where a student sees that happen. Each frame adds
/// one attempt, in the order the quantum service tried them.
/// </summary>
class RSAShorsAttemptsVisualization : IVisualization<RSA, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "RSA Shor's Algorithm Attempts";
    public string visualizationDefinition { get; } =
        "Shor's algorithm picks a random base a, checks gcd(a, N) classically, and runs the quantum circuit only " +
        "if a shares no factor with N. If the measurement can't be used, it starts over with a new base. This " +
        "table lists every base the RSA Shor's Algorithm solver tried, one step at a time.";
    public string source { get; } =
        "Shor, P. W. (1997). Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a " +
        "Quantum Computer. SIAM Journal on Computing, 26(5), 1484-1509.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.DynamicTable;
    // The solver a picture uses when none is named, which is how Redux_Frontend draws the picture before a Run.
    // The instant classical attack keeps that from calling the quantum service on every page load; it records no
    // Shor's run, so the picture before a Run is visualize(). Pick the RSA Shor's Algorithm solver to fill it in.
    public ISolver solver { get; } = new RSAFactoringAttackSolver();
    Type? IVisualization.StepShape => typeof(Assignment);

    // Color keys understood by both frontends (see Redux_Frontend components/theme.js).
    private const string NewestRowColor = "ElementHighlight";
    private const string SuccessColor = "Solution";

    // --- Constructors ---
    public RSAShorsAttemptsVisualization() { }

    // --- Methods ---

    /// <summary>Before a run: the table's columns and one row saying how it fills in.</summary>
    public API_TableJSON visualize(RSA problem) {
        var table = Table($"Shor's algorithm on N = {problem.modulus}: no attempts yet");
        table.rows.Add(new TableRow {
            id = "none",
            cells = new Dictionary<string, string> {
                ["attempt"] = "",
                ["a"] = "?",
                ["gcd"] = "",
                ["circuit"] = "",
                ["x"] = "",
                ["r"] = "",
                ["result"] = "Run the RSA Shor's Algorithm solver: each base it tries appears here.",
            },
        });
        return table;
    }

    /// <summary>One table per attempt, each with every attempt so far and the newest highlighted.</summary>
    public List<API_JSON> StepsVisualization(RSA problem, List<object> steps) {
        ShorsRun? run = ShorsRun.FromSteps(steps);
        var frames = new List<API_JSON>();
        if (run is null)
            return frames;
        if (run.Attempts.Count == 0) {
            frames.Add(Table(run.Classical switch {
                "even" => $"N = {run.N} is even, so it splits as 2 × {run.N / 2} without Shor's algorithm",
                "perfect_power" => $"N = {run.N} is a power of one prime, split without Shor's algorithm",
                "prime" => $"N = {run.N} is prime: there is nothing to split",
                _ => "The quantum service tried no bases",
            }));
            return frames;
        }

        for (int i = 0; i < run.Attempts.Count; i++) {
            ShorsAttempt newest = run.Attempts[i];
            string title = newest.Succeeded
                ? $"Attempt {i + 1}: a = {newest.A} splits {run.N} = {newest.Factors![0]} × {newest.Factors[1]}"
                : $"Attempt {i + 1}: a = {newest.A} fails, so the algorithm starts over with a new base";
            var table = Table(title);
            for (int k = 0; k <= i; k++)
                table.rows.Add(Row(run, k, k == i));
            frames.Add(table);
        }
        return frames;
    }

    private static API_TableJSON Table(string title) => new() {
        title = title,
        columns = new List<TableColumn> {
            new() { key = "attempt", label = "Attempt" },
            new() { key = "a", label = "Base a" },
            new() { key = "gcd", label = "gcd(a, N)" },
            new() { key = "circuit", label = "Circuit run?" },
            new() { key = "x", label = "Measured x" },
            new() { key = "r", label = "Period r" },
            new() { key = "result", label = "What happened" },
        },
    };

    private static TableRow Row(ShorsRun run, int index, bool newest) {
        ShorsAttempt a = run.Attempts[index];
        string? color = !newest ? null : a.Succeeded ? SuccessColor : NewestRowColor;
        return new TableRow {
            id = $"attempt-{index + 1}",
            color = color,
            cells = new Dictionary<string, string> {
                ["attempt"] = (index + 1).ToString(),
                ["a"] = a.A.ToString(),
                ["gcd"] = a.Gcd.ToString(),
                ["circuit"] = a.Circuit ? "Yes" : "No, gcd > 1",
                ["x"] = a.X?.ToString() ?? "",
                ["r"] = a.R?.ToString() ?? (a.Circuit ? "none found" : ""),
                ["result"] = a.Result(run.N),
            },
        };
    }
}
