namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// One value an attack has just worked out, recorded as one typed solver step (see RecoveredValues) and drawn as part of the
/// "what the attacker knows" table (RSAKnowledgeTableVisualization). Both RSA solvers record these, so the
/// same table can replay either solver's run.
/// </summary>
/// <param name="Variable">Which secret was found: one of the keys in <see cref="Secrets"/>.</param>
/// <param name="Value">The value found, as text.</param>
/// <param name="HowFound">A one-line explanation of how the attack found it.</param>
/// <param name="Letter">For a plaintext step in message mode, which letter of the message (from 0) it is.</param>
record RSAStep(string Variable, string Value, string HowFound, int? Letter = null) {

    public const string P = "p";
    public const string Q = "q";
    public const string Phi = "phi";
    public const string D = "d";
    public const string M = "m";

    /// <summary>The secret values, in the order a factoring attack finds them.</summary>
    public static readonly string[] Secrets = { P, Q, Phi, D, M };

    /// <summary>The value's name in the run's typed steps: the variable, or for one letter of a message, "m" and the
    /// letter's number from 1, such as "m3".</summary>
    public string Name => Letter is int letter ? $"{Variable}{letter + 1}" : Variable;

    /// <summary>The values a typed run recovered, in order (see <see cref="RecoveredValues.Read"/>).</summary>
    public static List<RSAStep> FromRun(IEnumerable<object> steps) =>
        RecoveredValues.Read(steps).Select(v => FromName(v.Name, v.Value, v.HowFound)).ToList();

    private static RSAStep FromName(string name, string value, string howFound) =>
        name.Length > M.Length && name.StartsWith(M, StringComparison.Ordinal) && int.TryParse(name[M.Length..], out int number)
            ? new RSAStep(M, value, howFound, number - 1)
            : new RSAStep(name, value, howFound);
}
