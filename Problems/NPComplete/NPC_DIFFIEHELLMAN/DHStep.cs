namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN;

/// <summary>
/// One value an attack has just worked out, recorded by a solver's GetSteps and drawn as part of the
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
}
