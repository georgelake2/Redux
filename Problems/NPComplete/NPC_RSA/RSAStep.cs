namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// One value an attack has just worked out, recorded by a solver's GetSteps and drawn as part of the
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
}
