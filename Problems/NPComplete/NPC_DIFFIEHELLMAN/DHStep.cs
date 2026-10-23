using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN;

/// <summary>
/// One value an attack has just worked out, recorded as one typed solver step (see RecoveredValues) and drawn as part of the
/// "what the attacker knows" table (DHKnowledgeTableVisualization). Both Diffie-Hellman solvers record these.
/// </summary>
/// <param name="Variable">Which secret was found: one of the keys in <see cref="Secrets"/>.</param>
/// <param name="Value">The value found, as text.</param>
/// <param name="HowFound">A one-line explanation of how the attack found it.</param>
/// <param name="Letter">For a plaintext step in message mode, which letter of the message (from 0) it is.</param>
record DHStep(string Variable, string Value, string HowFound, int? Letter = null) {

    public const string A = "a";
    public const string B = "b";
    public const string S = "s";
    public const string M = "m";

    /// <summary>
    /// The secret values, in table order. An attack finds a, then s, then the message; b is never needed,
    /// because one private key is enough.
    /// </summary>
    public static readonly string[] Secrets = { A, B, S, M };

    /// <summary>The value's name in the run's typed steps: the variable, or for one letter of a message, "m" and the
    /// letter's number from 1, such as "m3".</summary>
    public string Name => Letter is int letter ? $"{Variable}{letter + 1}" : Variable;

    /// <summary>The values a typed run recovered, in order (see <see cref="RecoveredValues.Read"/>).</summary>
    public static List<DHStep> FromRun(IEnumerable<object> steps) =>
        RecoveredValues.Read(steps).Select(v => FromName(v.Name, v.Value, v.HowFound)).ToList();

    private static DHStep FromName(string name, string value, string howFound) =>
        name.Length > M.Length && name.StartsWith(M, StringComparison.Ordinal) && int.TryParse(name[M.Length..], out int number)
            ? new DHStep(M, value, howFound, number - 1)
            : new DHStep(name, value, howFound);
}
