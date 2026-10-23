using System.Numerics;
using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Solvers;
using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Visualizations;

/// <summary>
/// "What the attacker knows": a table with one row per Diffie-Hellman value. Before a run it shows the public
/// values (p, g, A, B and, for a message, the ciphertexts), with every secret marked "?". Each recorded solver
/// step fills in one more secret: Alice's private key a, then the shared secret s, then the message letter by
/// letter. Bob's key b stays "?", which shows that one private key is enough.
/// </summary>
class DHKnowledgeTableVisualization : IVisualization<DIFFIEHELLMAN, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "Diffie-Hellman Attacker Knowledge Table";
    public string visualizationDefinition { get; } =
        "A table of every Diffie-Hellman value, showing which ones the attacker can see (p, g, the public values A " +
        "and B, and any ciphertext) and filling in the secret ones (Alice's private key, the shared secret and the " +
        "message) one step at a time as the attack recovers them. Bob's private key is never needed.";
    public string source { get; } =
        "Diffie, W., and Hellman, M. E. (1976). New Directions in Cryptography. IEEE Transactions on Information " +
        "Theory, 22(6), 644-654.";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.DynamicTable;
    public ISolver solver { get; } = new DHBruteForceDiscreteLogSolver();
    // Draws the typed steps the crypto solvers record (see RecoveredValues).
    Type? IVisualization.StepShape => typeof(Assignment);

    // Color keys understood by both frontends (see Redux_Frontend components/theme.js).
    private const string NewestRowColor = "ElementHighlight";
    private const string AnswerColor = "Solution";

    private const string Unknown = "?";

    /// <summary>How each secret is labelled in the table.</summary>
    private static readonly Dictionary<string, string> SecretLabels = new() {
        [DHStep.A] = "a (Alice's private key)",
        [DHStep.B] = "b (Bob's private key)",
        [DHStep.S] = "s (shared secret)",
        [DHStep.M] = "m (plaintext)",
    };

    // --- Constructors ---
    public DHKnowledgeTableVisualization() { }

    // --- Methods ---

    /// <summary>The table before any attack: the public values filled in, every secret unknown.</summary>
    public API_TableJSON visualize(DIFFIEHELLMAN problem) =>
        BuildTable(problem, new List<DHStep>(), "What the attacker sees: p, g and the public values A and B");

    /// <summary>One table per recorded step, each with every value found so far.</summary>
    public List<API_JSON> StepsVisualization(DIFFIEHELLMAN problem, List<object> steps) {
        List<DHStep> found = DHStep.FromRun(steps);
        var frames = new List<API_JSON>();
        for (int i = 0; i < found.Count; i++) {
            string title = $"Step {i + 1} of {found.Count}: found {Describe(problem, found[i])}";
            frames.Add(BuildTable(problem, found.Take(i + 1).ToList(), title));
        }
        return frames;
    }

    private static string Describe(DIFFIEHELLMAN problem, DHStep step) =>
        step.Letter is int letter
            ? $"letter {letter + 1} of {problem.ciphertexts.Count}"
            : SecretLabels[step.Variable];

    /// <summary>
    /// Builds one table. <paramref name="found"/> is every step so far, in order; its last entry is the newest
    /// and is highlighted, in the answer color once the attack is complete.
    /// </summary>
    private static API_TableJSON BuildTable(DIFFIEHELLMAN problem, List<DHStep> found, string title) {
        var table = new API_TableJSON {
            title = title,
            columns = new List<TableColumn> {
                new() { key = "variable", label = "Value" },
                new() { key = "value", label = "Number" },
                new() { key = "visibility", label = "Visible to the attacker?" },
                new() { key = "howFound", label = "How the attacker knows it" },
            },
        };

        table.rows.Add(PublicRow("p", "p", problem.modulus.ToString(), "Public parameter"));
        table.rows.Add(PublicRow("g", "g", problem.generator.ToString(), "Public parameter"));
        table.rows.Add(PublicRow("A", "A (Alice's public value)", problem.publicA.ToString(), "Sent by Alice: A = g^a mod p"));
        table.rows.Add(PublicRow("B", "B (Bob's public value)", problem.publicB.ToString(), "Sent by Bob: B = g^b mod p"));
        if (problem.isMessage)
            table.rows.Add(PublicRow("c", "c (one per letter)", string.Join(", ", problem.ciphertexts), "Intercepted ciphertext"));

        DHStep? newest = found.Count > 0 ? found[^1] : null;
        bool sharedSecretKnown = found.Any(s => s.Variable == DHStep.S);
        bool complete = problem.isMessage
            ? found.Count(s => s.Variable == DHStep.M) == problem.ciphertexts.Count
            : sharedSecretKnown;

        foreach (string secret in DHStep.Secrets) {
            if (secret == DHStep.M && !problem.isMessage)
                continue;
            List<DHStep> stepsForSecret = found.Where(s => s.Variable == secret).ToList();
            bool isKnown = stepsForSecret.Count > 0;
            string? color = null;
            if (isKnown && stepsForSecret[^1] == newest)
                color = complete ? AnswerColor : NewestRowColor;

            string howFound = isKnown ? stepsForSecret[^1].HowFound : "";
            if (secret == DHStep.B && sharedSecretKnown)
                howFound = "Never needed: with Alice's key, the shared secret is B^a mod p";

            table.rows.Add(new TableRow {
                id = secret,
                color = color,
                cells = new Dictionary<string, string> {
                    ["variable"] = SecretLabels[secret],
                    ["value"] = isKnown ? ValueText(problem, secret, stepsForSecret) : Unknown,
                    ["visibility"] = isKnown ? "No, but recovered" : "No, secret",
                    ["howFound"] = howFound,
                },
            });
        }
        return table;
    }

    /// <summary>
    /// The value shown for a secret. The plaintext is built up letter by letter, for example
    /// "8, 5, 12 = "HEL"", with "?" for letters not recovered yet.
    /// </summary>
    private static string ValueText(DIFFIEHELLMAN problem, string secret, List<DHStep> steps) {
        if (secret != DHStep.M)
            return steps[^1].Value;

        var numbers = new string[problem.ciphertexts.Count];
        var letters = new char[problem.ciphertexts.Count];
        Array.Fill(numbers, Unknown);
        Array.Fill(letters, '?');
        foreach (DHStep step in steps) {
            if (step.Letter is not int i)
                continue;
            numbers[i] = step.Value;
            letters[i] = BigInteger.TryParse(step.Value, out var code) && RSAAlphabet.Decode(code) is char ch ? ch : '?';
        }
        return $"{string.Join(", ", numbers)} = \"{new string(letters)}\"";
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
