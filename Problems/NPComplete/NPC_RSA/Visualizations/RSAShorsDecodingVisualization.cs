using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_RSA.Solvers;

namespace API.Problems.NPComplete.NPC_RSA.Visualizations;

/// <summary>
/// The classical half of Shor's algorithm: how the one measured number x becomes the factors of N, in five steps with
/// the working shown. (1) x ÷ 2^t is a decimal close to s ÷ r. (2) Its continued fractions give the simple fractions
/// near it, and the bottom numbers below N are the candidate periods. (3) The candidates and their multiples are
/// tested with a^k mod N = 1, and the first that passes is the period r. (4) h = a^(r/2) mod N is a number whose
/// square leaves remainder 1. (5) So N divides (h − 1)(h + 1) but neither factor alone, and the gcds pull p and q out.
/// Each frame adds one step, for the attempt that split N (or the last one that ran the circuit, up to where it failed).
/// </summary>
class RSAShorsDecodingVisualization : IVisualization<RSA, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "RSA Shor's Algorithm Decoding";
    public string visualizationDefinition { get; } =
        "The classical steps after the quantum measurement: turn x into a fraction, find the simple fraction " +
        "close to it with continued fractions, test the candidate periods with a^k mod N, cut the period in half, " +
        "and split N with two gcds. Shows the working for the attempt the RSA Shor's Algorithm solver used.";
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

    private const string NewestRowColor = "ElementHighlight";
    private const string SuccessColor = "Solution";

    /// <summary>One step of the decoding: its title, its lines of working, and why it works.</summary>
    private sealed record DecodeStep(string Title, List<string> Working, string Why, bool Last = false, bool Ok = false);

    // --- Constructors ---
    public RSAShorsDecodingVisualization() { }

    // --- Methods ---

    /// <summary>Before a run: the five steps, without numbers.</summary>
    public API_TableJSON visualize(RSA problem) {
        var table = Table($"From the measurement x to the factors of N = {problem.modulus}: run the RSA Shor's Algorithm solver to fill this in");
        string[] titles = {
            "1. Turn the measurement into a fraction", "2. Find the simple fraction it is close to",
            "3. Test the candidates: does a^k mod N equal 1?", "4. Cut the period in half",
            "5. Split it as a difference of squares, then use gcd",
        };
        for (int i = 0; i < titles.Length; i++)
            table.rows.Add(Row($"step-{i + 1}", titles[i], "?", "", null));
        return table;
    }

    /// <summary>One table per decoding step, each with the steps so far.</summary>
    public List<API_JSON> StepsVisualization(RSA problem, List<object> steps) {
        ShorsRun? run = ShorsRun.FromSteps(steps);
        var frames = new List<API_JSON>();
        if (run is null)
            return frames;

        ShorsAttempt? shown = run.Winner is { Circuit: true } ? run.Winner : run.LastCircuit;
        if (shown is null) {
            var table = Table(run.Winner is { } lucky
                ? $"No measurement to decode: a = {lucky.A} already shares a factor with N, gcd({lucky.A}, {run.N}) = {lucky.Gcd}, so {run.N} = {lucky.Factors![0]} × {lucky.Factors[1]}"
                : $"No measurement to decode for N = {run.N}");
            frames.Add(table);
            return frames;
        }

        List<DecodeStep> decode = Decode(run, shown);
        int attempt = run.Attempts.IndexOf(shown) + 1;
        for (int i = 0; i < decode.Count; i++) {
            DecodeStep newest = decode[i];
            string title = newest.Last
                ? newest.Ok
                    ? $"Attempt {attempt}, a = {shown.A}, x = {shown.X}: {run.N} = {shown.Factors![0]} × {shown.Factors[1]}"
                    : $"Attempt {attempt}, a = {shown.A}, x = {shown.X}: this measurement can't be used, so the algorithm starts over"
                : $"Attempt {attempt}, a = {shown.A}, x = {shown.X}: step {i + 1}";
            var table = Table(title);
            for (int k = 0; k <= i; k++) {
                DecodeStep step = decode[k];
                string? color = k != i ? null : step.Last && step.Ok ? SuccessColor : NewestRowColor;
                for (int line = 0; line < step.Working.Count; line++) {
                    table.rows.Add(Row($"step-{k + 1}-{line + 1}", line == 0 ? step.Title : "", step.Working[line],
                        line == 0 ? step.Why : "", color));
                }
            }
            frames.Add(table);
        }
        return frames;
    }

    /// <summary>The decoding steps for one attempt, stopping where it failed.</summary>
    private static List<DecodeStep> Decode(ShorsRun run, ShorsAttempt at) {
        int n = run.N, t = run.CountingQubits, a = at.A, x = at.X ?? 0;
        long size = 1L << t;
        var steps = new List<DecodeStep> {
            new("1. Turn the measurement into a fraction",
                new() { $"x = {x}  (binary {Convert.ToString(x, 2).PadLeft(t, '0')})", $"x ÷ 2^{t} = {x} ÷ {size} = {x / (double)size:0.00000}" },
                $"The circuit makes x land near a multiple of {size} ÷ r, so this decimal is close to a fraction s ÷ r with the period r on the bottom."),
        };
        if (at.Outcome == ShorsAttempt.XZero) {
            steps.Add(new("Start over", new() { "x = 0 gives the fraction 0" }, "It says nothing about r, so the algorithm picks a new base.", Last: true));
            return steps;
        }

        var convergents = at.Convergents ?? Array.Empty<int[]>();
        var candidates = convergents.Where(f => f[0] > 0 && f[1] > 1).ToList();
        steps.Add(new("2. Find the simple fraction it is close to",
            new() { $"continued fractions of {x} ÷ {size}:", string.Join("    ", convergents.Select(f => $"{f[0]}/{f[1]} = {f[0] / (double)f[1]:0.00000}")) },
            candidates.Count > 0
                ? $"The closest one with a bottom number below {n} is {candidates[^1][0]}/{candidates[^1][1]}, so the candidate period is k = {candidates[^1][1]}. The true period is k or a multiple of it."
                : $"No useful fraction has a bottom number below {n}."));

        var tests = (at.Tested ?? Array.Empty<int[]>())
            .Select(c => $"{a}^{c[0]} mod {n} = {c[1]}   {(c[1] == 1 ? "← yes, equals 1" : "(not 1)")}").ToList();
        if (at.R is not int r) {
            steps.Add(new("3. Test the candidates: does a^k mod N equal 1?", tests.Count > 0 ? tests : new() { "no candidates to test" },
                "None works: this shot landed between the peaks. The algorithm picks a new base.", Last: true));
            return steps;
        }
        tests.Add($"period r = {r}");
        steps.Add(new("3. Test the candidates: does a^k mod N equal 1?", tests,
            $"The period is the smallest k that brings {a}^k back to 1. A reduced fraction can hide it, which is why multiples are tried too."));
        if (at.Outcome == ShorsAttempt.OddPeriod) {
            steps.Add(new("Start over", new() { $"r = {r} is odd" }, "r ÷ 2 is not a whole number, so step 4 can't be done. The algorithm picks a new base.", Last: true));
            return steps;
        }

        int h = at.H ?? 0;
        long square = (long)h * h;
        steps.Add(new("4. Cut the period in half",
            new() {
                $"h = {a}^{r / 2} mod {n} = {h}",
                $"{a}^{r} = {a}^{r / 2} × {a}^{r / 2}, and step 3 found {a}^{r} mod {n} = 1",
                $"so h × h mod {n} = 1 too.  Check: {h} × {h} = {square}, and {square} ÷ {n} = {square / n} remainder {square % n}",
            },
            $"h is a number whose square leaves remainder 1 when divided by {n}. That one fact is all step 5 needs."));
        if (at.Outcome == ShorsAttempt.MinusOne) {
            steps.Add(new("Start over", new() { $"h = {h} = {n} − 1" }, $"h + 1 = {n} holds all of {n} and h − 1 holds none of it. The algorithm picks a new base.", Last: true));
            return steps;
        }

        long product = (long)(h - 1) * (h + 1);
        steps.Add(new("5. Split it as a difference of squares, then use gcd",
            new() {
                $"h × h − 1 = (h − 1) × (h + 1) = {h - 1} × {h + 1} = {product} = {product / n} × {n}",
                $"gcd({h - 1}, {n}) = {at.GcdMinus}",
                $"gcd({h + 1}, {n}) = {at.GcdPlus}",
                $"{n} = {at.Factors![0]} × {at.Factors[1]}",
            },
            $"{n} divides {h - 1} × {h + 1} but neither number on its own, so each one holds part of {n}. The gcd pulls that part out.",
            Last: true, Ok: true));
        return steps;
    }

    private static API_TableJSON Table(string title) => new() {
        title = title,
        columns = new List<TableColumn> {
            new() { key = "step", label = "Step" },
            new() { key = "working", label = "Working" },
            new() { key = "why", label = "Why" },
        },
    };

    private static TableRow Row(string id, string step, string working, string why, string? color) => new() {
        id = id,
        color = color,
        cells = new Dictionary<string, string> { ["step"] = step, ["working"] = working, ["why"] = why },
    };
}
