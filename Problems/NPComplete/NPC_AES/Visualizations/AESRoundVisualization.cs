using System.Globalization;
using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_AES.Solvers;

namespace API.Problems.NPComplete.NPC_AES.Visualizations;

/// <summary>
/// AES round by round: once the attack has recovered the key, replays how Alice's plaintext became the
/// intercepted ciphertext. Each frame is the 4x4 state (16 bytes, column by column as in FIPS 197) after one
/// operation: the input, the initial AddRoundKey, then SubBytes, ShiftRows, MixColumns and AddRoundKey for each of
/// the 10 rounds (no MixColumns in the last), 41 frames in all. The bytes an operation changed are highlighted, and
/// the last frame is exactly the ciphertext.
/// </summary>
class AESRoundVisualization : IVisualization<AES, API_TableJSON> {

    // --- Fields ---
    public string visualizationName { get; } = "AES Round-by-Round Encryption";
    public string visualizationDefinition { get; } =
        "The 4x4 grid of bytes AES works on, shown after every operation of Alice's encryption once the attack has " +
        "found the key: SubBytes replaces each byte through the S-box, ShiftRows shifts row i left by i places, " +
        "MixColumns mixes each column, and AddRoundKey XORs in the round key. Changed bytes are highlighted; ten rounds " +
        "later the grid is the intercepted ciphertext.";
    public string source { get; } =
        "National Institute of Standards and Technology (2001, updated 2023). Advanced Encryption Standard (AES). " +
        "FIPS PUB 197, Appendix B (the same key and plaintext, worked round by round).";
    public string sourceFile { get; } = SourceFile.Path();
    public string[] contributors { get; } = { "George Lake" };
    public VisualizationType visualizationType { get; } = VisualizationType.DynamicTable;
    public ISolver solver { get; } = new AESBruteForceKeySearchSolver();
    // Draws the typed steps the crypto solvers record (see RecoveredValues).
    Type? IVisualization.StepShape => typeof(Assignment);

    // Color keys understood by both frontends (see Redux_Frontend components/theme.js).
    private const string ChangedColor = "ElementHighlight";
    private const string AnswerColor = "Solution";

    private static readonly Dictionary<string, string> Explanations = new() {
        [AESCipher.SubBytesStep] = "every byte replaced through the S-box",
        [AESCipher.ShiftRowsStep] = "row i shifted i places to the left",
        [AESCipher.MixColumnsStep] = "each column multiplied by a fixed matrix in GF(2^8)",
        [AESCipher.AddRoundKeyStep] = "XOR with the round key",
    };

    // --- Constructors ---
    public AESRoundVisualization() { }

    // --- Methods ---

    /// <summary>Before the attack, only the ciphertext is known: shown as the state it ended in.</summary>
    public API_TableJSON visualize(AES problem) =>
        Grid(problem.ciphertext, null,
            "The intercepted ciphertext as AES's 4x4 state. Once the attack finds the key, the steps replay Alice's " +
            "encryption round by round", null);

    /// <summary>
    /// One grid per operation of Alice's encryption under the recovered key, or no frames if the attack found no
    /// key. The plaintext is the known one in Eve's view, and the decrypted block (message and padding) otherwise.
    /// </summary>
    public List<API_JSON> StepsVisualization(AES problem, List<object> steps) {
        string? keyHex = AESStep.FromRun(steps).LastOrDefault(s => s.Variable == AESStep.Key)?.Value;
        if (keyHex is null || AES.TryParseBlock(keyHex) is not byte[] key)
            return new List<API_JSON>();
        byte[] plaintext = problem.knownPlaintext ?? AESCipher.Decrypt(problem.ciphertext, key);

        List<AESRoundState> trace = AESCipher.EncryptWithTrace(plaintext, key);
        var frames = new List<API_JSON>();
        for (int i = 0; i < trace.Count; i++) {
            AESRoundState state = trace[i];
            bool last = i == trace.Count - 1;
            string title = $"Step {i + 1} of {trace.Count}: {Describe(problem, state)}";
            if (last)
                title += " = the intercepted ciphertext";
            frames.Add(Grid(state.State, i == 0 ? null : trace[i - 1].State, title, last ? AnswerColor : null));
        }
        return frames;
    }

    private static string Describe(AES problem, AESRoundState state) {
        if (state.Operation == AESCipher.Input)
            return problem.isMessage ? "Alice's message and its padding, as ASCII bytes" : "the known plaintext";
        string where = state.Round == 0 ? "Before round 1" : $"Round {state.Round} of {AESCipher.Rounds}";
        string what = $"{where}, {state.Operation}: {Explanations[state.Operation]}";
        if (state.RoundKey is byte[] roundKey)
            what += $" {state.Round} ({AES.Hex(roundKey)}{(state.Round == 0 ? ", the key itself" : "")})";
        return what;
    }

    /// <summary>
    /// The state as a 4x4 table: row r, column c holds byte r + 4c. Bytes that differ from
    /// <paramref name="previous"/> are highlighted; <paramref name="rowColor"/> colors the whole grid.
    /// </summary>
    private static API_TableJSON Grid(byte[] state, byte[]? previous, string title, string? rowColor) {
        var table = new API_TableJSON {
            title = title,
            columns = new List<TableColumn> { new() { key = "row", label = "" } },
        };
        for (int c = 0; c < 4; c++)
            table.columns.Add(new TableColumn { key = $"c{c}", label = $"Column {c}" });

        for (int r = 0; r < 4; r++) {
            var cells = new Dictionary<string, string> { ["row"] = $"Row {r}" };
            var changed = new Dictionary<string, string>();
            for (int c = 0; c < 4; c++) {
                int index = r + 4 * c;
                cells[$"c{c}"] = state[index].ToString("x2", CultureInfo.InvariantCulture);
                if (previous is not null && previous[index] != state[index])
                    changed[$"c{c}"] = ChangedColor;
            }
            table.rows.Add(new TableRow {
                id = $"r{r}",
                color = rowColor,
                cells = cells,
                cellColors = rowColor is null && changed.Count > 0 ? changed : null,
            });
        }
        return table;
    }
}
