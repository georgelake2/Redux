using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// One base the quantum service tried while running Shor's algorithm (its /shors-traced endpoint): the base a and
/// gcd(a, N), and for a base that needed the circuit, the multipliers a^(2^j) mod N, the measured x, the continued-
/// fraction convergents of x / 2^t, the candidate periods tested with a^k mod N, the period r, h = a^(r/2) mod N and
/// the two gcds. <see cref="Outcome"/> says why the attempt ended: one of the constants below.
/// </summary>
record ShorsAttempt(
    [property: JsonPropertyName("a")] int A,
    [property: JsonPropertyName("gcd")] int Gcd,
    [property: JsonPropertyName("circuit")] bool Circuit,
    [property: JsonPropertyName("outcome")] string Outcome,
    [property: JsonPropertyName("factors")] int[]? Factors = null,
    [property: JsonPropertyName("multipliers")] int[]? Multipliers = null,
    [property: JsonPropertyName("x")] int? X = null,
    [property: JsonPropertyName("convergents")] int[][]? Convergents = null,
    [property: JsonPropertyName("tested")] int[][]? Tested = null,
    [property: JsonPropertyName("r")] int? R = null,
    [property: JsonPropertyName("h")] int? H = null,
    [property: JsonPropertyName("gcd_minus")] int? GcdMinus = null,
    [property: JsonPropertyName("gcd_plus")] int? GcdPlus = null) {

    public const string Lucky = "lucky";
    public const string Factored = "factored";
    public const string XZero = "x_zero";
    public const string NoPeriod = "no_period";
    public const string OddPeriod = "odd_period";
    public const string MinusOne = "minus_one";

    public bool Succeeded => Outcome is Lucky or Factored;

    /// <summary>One sentence on how the attempt ended, for the attempts table and the knowledge table.</summary>
    public string Result(int n) => Outcome switch {
        Lucky => $"gcd({A}, {n}) = {Gcd} is already a factor: {n} = {Factors![0]} × {Factors[1]}, no circuit needed",
        Factored => $"r = {R}, h = {H}, gcd({H} − 1, {n}) = {GcdMinus} and gcd({H} + 1, {n}) = {GcdPlus}: {n} = {Factors![0]} × {Factors[1]}",
        XZero => "x = 0 gives the fraction 0, which says nothing about r. Start over",
        NoPeriod => $"no candidate k gives {A}^k mod {n} = 1: this shot landed between peaks. Start over",
        OddPeriod => $"r = {R} is odd, so r ÷ 2 is not a whole number. Start over",
        MinusOne => $"h = {A}^{R / 2} mod {n} = {H} = {n} − 1, so h + 1 holds all of {n}. Start over",
        _ => Outcome,
    };
}

/// <summary>
/// The quantum service's record of one Shor's run on N: every attempt in order, the last one the one that split N.
/// <see cref="Classical"/> is set instead when N was split without the algorithm ("even", "perfect_power", "prime").
/// </summary>
record ShorsRun(
    [property: JsonPropertyName("n")] int N,
    [property: JsonPropertyName("counting_qubits")] int CountingQubits,
    [property: JsonPropertyName("work_qubits")] int WorkQubits,
    [property: JsonPropertyName("attempts")] List<ShorsAttempt> Attempts,
    [property: JsonPropertyName("classical")] string? Classical = null) {

    /// <summary>The name the record goes by in the RSA Shor's solver's Done step (see RecoveredValues.Record).</summary>
    public const string StepName = "shorsRun";

    private static readonly JsonSerializerOptions Options = new() {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>The attempt that split N, or null.</summary>
    public ShorsAttempt? Winner => Attempts.LastOrDefault(a => a.Succeeded);

    /// <summary>The last attempt that ran the circuit: the winner if it needed one, otherwise the latest failure.</summary>
    public ShorsAttempt? LastCircuit => Attempts.LastOrDefault(a => a.Circuit);

    public string ToJson() => JsonSerializer.Serialize(this, Options);

    /// <summary>Reads a record, or returns null if the text is not one.</summary>
    public static ShorsRun? FromJson(string? json) {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try {
            var run = JsonSerializer.Deserialize<ShorsRun>(json, Options);
            return run is { N: > 0, Attempts: not null } ? run : null;
        } catch (JsonException) {
            return null;
        }
    }

    /// <summary>The record carried by a run of the RSA Shor's solver, or null for any other run.</summary>
    public static ShorsRun? FromSteps(IEnumerable<object> steps) =>
        FromJson(RecoveredValues.DoneValue(steps, StepName));
}

/// <summary>
/// The last few quantum service replies, by N. One Run in Redux_Frontend asks for the answer and the picture at the same
/// moment, and each request runs the solver; Shor's algorithm is random, so two separate service calls would show a
/// picture of a different run than the answer. Requests for the same N that arrive while a call is in flight, or within
/// <see cref="Reuse"/> after it (the two requests of one Run can arrive a moment apart), share that call. Pressing Run
/// again gets a new run.
/// </summary>
static class ShorsReplies {

    public static readonly TimeSpan Reuse = TimeSpan.FromSeconds(3);

    private static readonly ConcurrentDictionary<string, Lazy<(string Reply, DateTime Finished)>> Calls = new();

    public static string Get(string key, Func<string> call) {
        var entry = Calls.AddOrUpdate(key,
            _ => Start(call),
            (_, old) => old.IsValueCreated && DateTime.UtcNow - old.Value.Finished > Reuse ? Start(call) : old);
        try {
            return entry.Value.Reply;
        } catch {
            // A failed call is not reused: the next request tries again.
            Calls.TryRemove(new KeyValuePair<string, Lazy<(string, DateTime)>>(key, entry));
            throw;
        }
    }

    private static Lazy<(string, DateTime)> Start(Func<string> call) =>
        new(() => (call(), DateTime.UtcNow), LazyThreadSafetyMode.ExecutionAndPublication);
}
