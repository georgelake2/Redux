using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_RSA.Solvers;

namespace API.Problems.NPComplete.NPC_RSA.Visualizations;

/// <summary>
/// "What the attacker knows": a table with one row per RSA value. Before a run it shows the public key and
/// the ciphertext, with every secret marked "?". Each recorded solver step then fills in one more secret
/// (in message mode, one more letter of the plaintext), with the newest row highlighted and the plaintext
/// marked as the solution once it is complete.
///
/// The frames are built from the steps the chosen solver actually recorded, so the factoring attack fills
/// in p, q, phi, d and the plaintext, while the plaintext search goes straight to the plaintext and never
/// learns the key.
/// </summary>
class RSAKnowledgeTableVisualization : IVisualization<RSA, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "RSA Attacker Knowledge Table";
    public string visualizationDefinition { get; } =
        "A table of every RSA value, showing which ones the attacker can see (the public key and the " +
        "ciphertext) and filling in the secret ones (p, q, phi, d and the plaintext) one step at a time as " +
        "the attack recovers them.";
    public string source { get; } =
        "Rivest, R. L., Shamir, A., and Adleman, L. (1978). A Method for Obtaining Digital Signatures and " +
        "Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.DynamicTable;
    public ISolver solver { get; } = new RSAFactoringAttackSolver();
    // Draws the typed steps the crypto solvers record (see RecoveredValues).
    Type? IVisualization.StepShape => typeof(Assignment);

    // Color keys understood by both frontends (see Redux_Frontend components/theme.js).
    private const string NewestRowColor = "ElementHighlight";
    private const string PlaintextColor = "Solution";

    private const string Unknown = "?";

    /// <summary>How each secret is labelled in the table.</summary>
    private static readonly Dictionary<string, string> SecretLabels = new() {
        [RSAStep.P] = "p",
        [RSAStep.Q] = "q",
        [RSAStep.Phi] = "φ",
        [RSAStep.D] = "d",
        [RSAStep.M] = "m (plaintext)",
    };

    // --- Constructors ---
    public RSAKnowledgeTableVisualization() { }

    // --- Methods ---

    /// <summary>The table before any attack: the public values filled in, every secret unknown.</summary>
    public API_TableJSON visualize(RSA problem) =>
        BuildTable(problem, new List<RSAStep>(), "What the attacker sees: the public key (N, e) and the ciphertext");

    /// <summary>One table per recorded step, each with every value found so far.</summary>
    public List<API_JSON> StepsVisualization(RSA problem, List<object> steps) {
        List<RSAStep> found = RSAStep.FromRun(steps);
        var frames = new List<API_JSON>();
        for (int i = 0; i < found.Count; i++) {
            string title = $"Step {i + 1} of {found.Count}: found {Describe(problem, found[i])}";
            frames.Add(BuildTable(problem, found.Take(i + 1).ToList(), title));
        }
        return frames;
    }

    private static string Describe(RSA problem, RSAStep step) =>
        step.Letter is int letter
            ? $"letter {letter + 1} of {problem.ciphertexts.Count}"
            : SecretLabels[step.Variable];

    /// <summary>
    /// Builds one table. <paramref name="found"/> is every step so far, in order; its last entry is the
    /// newest and is highlighted.
    /// </summary>
    private static API_TableJSON BuildTable(RSA problem, List<RSAStep> found, string title) {
        var table = new API_TableJSON {
            title = title,
            columns = new List<TableColumn> {
                new() { key = "variable", label = "Value" },
                new() { key = "value", label = "Number" },
                new() { key = "visibility", label = "Visible to the attacker?" },
                new() { key = "howFound", label = "How the attacker knows it" },
            },
        };

        table.rows.Add(PublicRow("N", problem.modulus.ToString(), "Public key"));
        table.rows.Add(PublicRow("e", problem.publicExponent.ToString(), "Public key"));
        table.rows.Add(PublicRow(problem.isMessage ? "c (one per letter)" : "c", string.Join(", ", problem.ciphertexts),
            "Intercepted ciphertext", id: "c"));

        RSAStep? newest = found.Count > 0 ? found[^1] : null;
        foreach (string secret in RSAStep.Secrets) {
            List<RSAStep> stepsForSecret = found.Where(s => s.Variable == secret).ToList();
            bool isKnown = stepsForSecret.Count > 0;
            bool isNewest = isKnown && stepsForSecret[^1] == newest;
            bool plaintextComplete = secret == RSAStep.M && stepsForSecret.Count == problem.ciphertexts.Count;

            string? color = null;
            if (isNewest)
                color = plaintextComplete ? PlaintextColor : NewestRowColor;

            table.rows.Add(new TableRow {
                id = secret,
                color = color,
                cells = new Dictionary<string, string> {
                    ["variable"] = SecretLabels[secret],
                    ["value"] = isKnown ? ValueText(problem, secret, stepsForSecret) : Unknown,
                    ["visibility"] = isKnown ? "No, but recovered" : "No, secret",
                    ["howFound"] = isKnown ? stepsForSecret[^1].HowFound : "",
                },
            });
        }
        return table;
    }

    /// <summary>
    /// The value shown for a secret. The plaintext in message mode is built up letter by letter, for
    /// example "8, 5, 12 = "HEL"", with "?" for letters not recovered yet.
    /// </summary>
    private static string ValueText(RSA problem, string secret, List<RSAStep> steps) {
        if (secret != RSAStep.M || !problem.isMessage)
            return steps[^1].Value;

        var numbers = new string[problem.ciphertexts.Count];
        var letters = new char[problem.ciphertexts.Count];
        Array.Fill(numbers, Unknown);
        Array.Fill(letters, '?');
        foreach (RSAStep step in steps) {
            if (step.Letter is not int i)
                continue;
            numbers[i] = step.Value;
            letters[i] = System.Numerics.BigInteger.TryParse(step.Value, out var code) && RSAAlphabet.Decode(code) is char ch
                ? ch
                : '?';
        }
        return $"{string.Join(", ", numbers)} = \"{new string(letters)}\"";
    }

    private static TableRow PublicRow(string label, string value, string howFound, string? id = null) => new() {
        id = id ?? label,
        cells = new Dictionary<string, string> {
            ["variable"] = label,
            ["value"] = value,
            ["visibility"] = "Yes",
            ["howFound"] = howFound,
        },
    };
}
