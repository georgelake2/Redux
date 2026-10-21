using System.Globalization;
using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Problems.NPComplete.NPC_AES.Solvers;

namespace API.Problems.NPComplete.NPC_AES.Visualizations;

/// <summary>
/// "What the attacker knows": a table with one row per value in the AES key search. Before a run it shows what
/// Eve sees (the key with its last k bits as "?", k, the ciphertext and, in Eve's view, the known plaintext), with
/// every secret marked "?". Each recorded solver step fills in one more secret: the missing key bits, the full key,
/// then the message.
/// </summary>
class AESKnowledgeTableVisualization : IVisualization<AES, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "AES Attacker Knowledge Table";
    public string visualizationDefinition { get; } =
        "A table of every value in the key search, showing what the attacker can see (the known key bits, how many " +
        "are missing, the ciphertext and any known plaintext) and filling in the secret ones (the missing key bits, " +
        "the full key and the message) one step at a time as the attack recovers them.";
    public string source { get; } =
        "National Institute of Standards and Technology (2001, updated 2023). Advanced Encryption Standard (AES). " +
        "FIPS PUB 197.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.DynamicTable;
    public ISolver solver { get; } = new AESBruteForceKeySearchSolver();

    // Color keys understood by both frontends (see Redux_Frontend components/theme.js).
    private const string NewestRowColor = "ElementHighlight";
    private const string AnswerColor = "Solution";

    private const string Unknown = "?";

    /// <summary>How each secret is labelled in the table.</summary>
    private static readonly Dictionary<string, string> SecretLabels = new() {
        [AESStep.Bits] = "Missing key bits",
        [AESStep.Key] = "Full key",
        [AESStep.M] = "Message (plaintext)",
    };

    // --- Constructors ---
    public AESKnowledgeTableVisualization() { }

    // --- Methods ---

    /// <summary>The table before any attack: what Eve sees filled in, every secret unknown.</summary>
    public API_TableJSON visualize(AES problem) =>
        BuildTable(problem, new List<AESStep>(), "What the attacker sees: the ciphertext and all but the last k key bits");

    /// <summary>One table per recorded step, each with every value found so far.</summary>
    public List<API_JSON> StepsVisualization(AES problem, List<object> steps) {
        List<AESStep> found = steps.OfType<AESStep>().ToList();
        var frames = new List<API_JSON>();
        for (int i = 0; i < found.Count; i++) {
            string title = $"Step {i + 1} of {found.Count}: found the {SecretLabels[found[i].Variable].ToLowerInvariant()}";
            frames.Add(BuildTable(problem, found.Take(i + 1).ToList(), title));
        }
        return frames;
    }

    /// <summary>
    /// Builds one table. <paramref name="found"/> is every step so far, in order; its last entry is the newest
    /// and is highlighted, in the answer color once the attack is complete.
    /// </summary>
    private static API_TableJSON BuildTable(AES problem, List<AESStep> found, string title) {
        var table = new API_TableJSON {
            title = title,
            columns = new List<TableColumn> {
                new() { key = "variable", label = "Value" },
                new() { key = "value", label = "Contents" },
                new() { key = "visibility", label = "Visible to the attacker?" },
                new() { key = "howFound", label = "How the attacker knows it" },
            },
        };

        table.rows.Add(PublicRow("known", "Known key bits (hex)", problem.KnownKeyText(),
            $"Given: every bit except the last {problem.unknownBits}, so the search is small enough to finish"));
        table.rows.Add(PublicRow("k", "k (unknown key bits)",
            $"{problem.unknownBits}, so 2^{problem.unknownBits} = {problem.candidateCount.ToString("N0", CultureInfo.InvariantCulture)} candidate keys",
            "Given: how many key bits are missing"));
        if (problem.knownPlaintext is byte[] plaintext)
            table.rows.Add(PublicRow("pt", "Known plaintext (hex)", AES.Hex(plaintext), "Known to the attacker, with its ciphertext"));
        table.rows.Add(PublicRow("ct", "Ciphertext (hex)", AES.Hex(problem.ciphertext), "Intercepted ciphertext"));

        AESStep? newest = found.Count > 0 ? found[^1] : null;
        string lastSecret = problem.isMessage ? AESStep.M : AESStep.Key;
        bool complete = found.Any(s => s.Variable == lastSecret);

        foreach (string secret in AESStep.Secrets) {
            if (secret == AESStep.M && !problem.isMessage)
                continue;
            AESStep? step = found.LastOrDefault(s => s.Variable == secret);
            string? color = null;
            if (step is not null && step == newest)
                color = complete ? AnswerColor : NewestRowColor;

            table.rows.Add(new TableRow {
                id = secret,
                color = color,
                cells = new Dictionary<string, string> {
                    ["variable"] = SecretLabels[secret],
                    ["value"] = step?.Value ?? Unknown,
                    ["visibility"] = step is null ? "No, secret" : "No, but recovered",
                    ["howFound"] = step?.HowFound ?? "",
                },
            });
        }
        return table;
    }

    private static TableRow PublicRow(string id, string label, string value, string howFound) => new() {
        id = id,
        cells = new Dictionary<string, string> {
            ["variable"] = label,
            ["value"] = value,
            ["visibility"] = "Yes",
            ["howFound"] = howFound,
        },
    };
}
