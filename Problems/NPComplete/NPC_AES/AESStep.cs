using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_AES;

/// <summary>
/// One value an attack has just worked out, recorded as one typed solver step (see RecoveredValues) and drawn as part of the
/// "what the attacker knows" table (AESKnowledgeTableVisualization). The round-by-round visualization reads the
/// recovered key from these steps to replay the encryption.
/// </summary>
/// <param name="Variable">Which secret was found: one of the keys in <see cref="Secrets"/>.</param>
/// <param name="Value">The value found, as text (hex for key material).</param>
/// <param name="HowFound">A one-line explanation of how the attack found it.</param>
record AESStep(string Variable, string Value, string HowFound) {

    public const string Bits = "bits";
    public const string Key = "key";
    public const string M = "m";

    /// <summary>The secret values, in table order: the missing key bits, then the whole key, then the message.</summary>
    public static readonly string[] Secrets = { Bits, Key, M };

    /// <summary>The values a typed run recovered, in order (see <see cref="RecoveredValues.Read"/>).</summary>
    public static List<AESStep> FromRun(IEnumerable<object> steps) =>
        RecoveredValues.Read(steps).Select(v => new AESStep(v.Name, v.Value, v.HowFound)).ToList();
}
