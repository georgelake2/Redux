using System.Text.Json;
using API.Interfaces;
using API.Interfaces.JSON_Objects;
using API.Interfaces.JSON_Objects.Tables;
using API.Problems.NPComplete.NPC_RSA;
using API.Problems.NPComplete.NPC_RSA.Solvers;
using API.Problems.NPComplete.NPC_RSA.Visualizations;
using Xunit;

namespace redux_tests;

#pragma warning disable CS1591

/// <summary>
/// Tests for the Shor's visualizations on RSA (circuit, attempts, decoding) and for the record the RSA Shor's solver
/// carries to them. The quantum service is a fake that returns a fixed /shors-traced reply, so the run is known:
/// N = 55, attempt 1 with a = 12 measures x = 0 and fails, attempt 2 with a = 48 measures x = 1843, which gives
/// r = 20, h = 34 and 55 = 5 × 11. The reply was produced by quantumsolver's shors_traced.trace with those
/// measurements fixed.
/// </summary>
public class RSAShorsVisualizations_Tests {

    private const string Lesson = "(55,3,52)";

    private const string TwoAttempts =
        """{"n": 55, "counting_qubits": 12, "work_qubits": 6, "attempts": [{"a": 12, "gcd": 1, "circuit": true, "multipliers": [12, 34, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], "x": 0, "convergents": [], "tested": [], "r": null, "h": null, "outcome": "x_zero"}, {"a": 48, "gcd": 1, "circuit": true, "multipliers": [48, 49, 36, 31, 26, 16, 36, 31, 26, 16, 36, 31], "x": 1843, "convergents": [[0, 1], [1, 2], [4, 9], [9, 20]], "tested": [[20, 1]], "r": 20, "h": 34, "outcome": "factored", "gcd_minus": 11, "gcd_plus": 5, "factors": [5, 11]}], "classical": null, "answer": [5, 11]}""";

    private const string Lucky =
        """{"n": 55, "counting_qubits": 12, "work_qubits": 6, "attempts": [{"a": 22, "gcd": 11, "circuit": false, "outcome": "lucky", "factors": [5, 11]}], "classical": null, "answer": [5, 11]}""";

    private static List<object> StepsOf(string reply, string instance = Lesson) {
        ISolver solver = new RSAShorsQuantumSolver { CallService = _ => reply };
        return solver.Run(instance, withSteps: true).Steps.ToList();
    }

    private static JsonElement D3(API_JSON frame) => Assert.IsType<API_QUANTUMCIRCUIT>(frame).d3!.Value;

    private static string Caption(API_JSON frame) =>
        D3(frame).GetProperty("metadata").GetProperty("caption").GetString()!;

    // --- The record the solver carries ---

    [Fact]
    public void Solver_Carries_The_Services_Record_And_Says_Which_Attempt_Split_N() {
        var steps = StepsOf(TwoAttempts);
        ShorsRun run = Assert.IsType<ShorsRun>(ShorsRun.FromSteps(steps));
        Assert.Equal(55, run.N);
        Assert.Equal(2, run.Attempts.Count);
        Assert.Equal(48, run.Winner!.A);

        var p = RSAStep.FromRun(steps)[0];
        Assert.Equal("5", p.Value);
        Assert.Contains("on its second base, after 1 that failed", p.HowFound);
        Assert.Contains("x = 1843", p.HowFound);
    }

    [Fact]
    public void Solver_Asks_The_Traced_Endpoint() {
        Assert.Equal("/shors-traced", RSAShorsQuantumSolver.Endpoint);
        string? sent = null;
        var solver = new RSAShorsQuantumSolver { CallService = body => { sent = body; return TwoAttempts; } };
        Assert.Equal("13", solver.solve(new RSA(Lesson)));
        Assert.Equal("55", sent);
    }

    [Fact]
    public void Knowledge_Table_Is_Unchanged_By_The_Record() {
        var steps = StepsOf(TwoAttempts);
        var frames = new RSAKnowledgeTableVisualization().StepsVisualization(new RSA(Lesson), steps);
        Assert.Equal(5, frames.Count); // p, q, phi, d, m: the record is not a recovered value
    }

    [Fact]
    public void Other_Solvers_Runs_Have_No_Record() {
        ISolver attack = new RSAFactoringAttackSolver();
        var steps = attack.Run(Lesson, withSteps: true).Steps.ToList();
        Assert.Null(ShorsRun.FromSteps(steps));
        Assert.Empty(new RSAShorsCircuitVisualization().StepsVisualization(new RSA(Lesson), steps));
        Assert.Empty(new RSAShorsAttemptsVisualization().StepsVisualization(new RSA(Lesson), steps));
        Assert.Empty(new RSAShorsDecodingVisualization().StepsVisualization(new RSA(Lesson), steps));
    }

    // --- Circuit ---

    [Fact]
    public void Circuit_Before_A_Run_Has_The_Shape_For_N() {
        var d3 = D3(new RSAShorsCircuitVisualization().visualize(new RSA(Lesson)));
        Assert.Equal(13, d3.GetProperty("qubits").GetArrayLength()); // c0..c11 and work
        var gates = d3.GetProperty("gates").EnumerateArray().ToList();
        Assert.Equal(1 + 12 + 12 + 12 + 12, gates.Count); // X, H, multiplies, QFT†, measurements
        Assert.Contains(gates, g => g.GetProperty("label").GetString() == "×a^4");
        Assert.Equal(4, d3.GetProperty("overlays").GetArrayLength());
        Assert.True(d3.GetProperty("metadata").GetProperty("readOnly").GetBoolean());
    }

    [Fact]
    public void Circuit_Steps_Through_The_Winning_Attempt_One_Column_At_A_Time() {
        var frames = new RSAShorsCircuitVisualization().StepsVisualization(new RSA(Lesson), StepsOf(TwoAttempts));
        Assert.Equal(12 + 3, frames.Count);
        Assert.Equal(13, D3(frames[0]).GetProperty("gates").GetArrayLength()); // X and 12 H
        Assert.Equal(14, D3(frames[1]).GetProperty("gates").GetArrayLength()); // plus ×48
        var multiplies = D3(frames[^1]).GetProperty("gates").EnumerateArray()
            .Where(g => g.GetProperty("type").GetString() == "multiply")
            .Select(g => g.GetProperty("label").GetString()).ToList();
        Assert.Equal(new[] { "×48", "×49", "×36", "×31" }, multiplies.Take(4));
        Assert.StartsWith("Attempt 2, a = 48.", Caption(frames[0]));
        Assert.Contains("x = 1843", Caption(frames[^1]));
        Assert.Contains("55 = 5 × 11", Caption(frames[^1]));
    }

    [Fact]
    public void Circuit_Explains_A_Lucky_Base_That_Needed_No_Circuit() {
        var frame = Assert.Single(new RSAShorsCircuitVisualization().StepsVisualization(new RSA(Lesson), StepsOf(Lucky)));
        Assert.Contains("gcd(22, 55) = 11", Caption(frame));
    }

    // --- Attempts ---

    [Fact]
    public void Attempts_Add_One_Row_Per_Base() {
        var frames = new RSAShorsAttemptsVisualization().StepsVisualization(new RSA(Lesson), StepsOf(TwoAttempts))
            .Cast<API_TableJSON>().ToList();
        Assert.Equal(2, frames.Count);
        Assert.Single(frames[0].rows);
        Assert.Contains("fails", frames[0].title);
        Assert.Contains("x = 0", frames[0].rows[0].cells["result"]);
        Assert.Equal(2, frames[1].rows.Count);
        Assert.Equal("Solution", frames[1].rows[1].color);
        Assert.Equal("1843", frames[1].rows[1].cells["x"]);
        Assert.Equal("20", frames[1].rows[1].cells["r"]);
        Assert.Contains("55 = 5 × 11", frames[1].title);
    }

    [Fact]
    public void Attempts_Show_A_Lucky_Base() {
        var frame = Assert.IsType<API_TableJSON>(Assert.Single(
            new RSAShorsAttemptsVisualization().StepsVisualization(new RSA(Lesson), StepsOf(Lucky))));
        Assert.Equal("No, gcd > 1", frame.rows[0].cells["circuit"]);
        Assert.Contains("no circuit needed", frame.rows[0].cells["result"]);
    }

    // --- Decoding ---

    [Fact]
    public void Decoding_Shows_The_Five_Steps_For_The_Winner() {
        var frames = new RSAShorsDecodingVisualization().StepsVisualization(new RSA(Lesson), StepsOf(TwoAttempts))
            .Cast<API_TableJSON>().ToList();
        Assert.Equal(5, frames.Count);
        var rows = frames[^1].rows;
        string Working(string startsWith) => rows.Single(r => r.cells["working"].StartsWith(startsWith, StringComparison.Ordinal)).cells["working"];
        Assert.Equal("x ÷ 2^12 = 1843 ÷ 4096 = 0.44995", Working("x ÷"));
        Assert.Contains("9/20 = 0.45000", Working("0/1"));
        Assert.Equal("48^20 mod 55 = 1   ← yes, equals 1", Working("48^20 mod"));
        Assert.Equal("h = 48^10 mod 55 = 34", Working("h ="));
        Assert.Equal("gcd(33, 55) = 11", Working("gcd(33"));
        Assert.Equal("gcd(35, 55) = 5", Working("gcd(35"));
        Assert.Contains("55 = 5 × 11", frames[^1].title);
        Assert.Equal("Solution", rows[^1].color);
    }

    [Fact]
    public void Decoding_Before_A_Run_Lists_The_Steps() {
        var table = new RSAShorsDecodingVisualization().visualize(new RSA(Lesson));
        Assert.Equal(5, table.rows.Count);
        Assert.StartsWith("1.", table.rows[0].cells["step"]);
    }

    // --- Sharing one service call between the answer and the picture ---

    [Fact]
    public async Task Requests_For_The_Same_N_Share_One_Call_While_It_Runs() {
        int calls = 0;
        string key = $"test-{Guid.NewGuid()}";
        using var gate = new ManualResetEventSlim(false);
        string Call() {
            Interlocked.Increment(ref calls);
            gate.Wait(TimeSpan.FromSeconds(5));
            return "reply";
        }
        var first = Task.Run(() => ShorsReplies.Get(key, Call));
        var second = Task.Run(() => ShorsReplies.Get(key, Call));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        gate.Set();
        Assert.Equal("reply", await first);
        Assert.Equal("reply", await second);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void A_Failed_Call_Is_Not_Reused() {
        string key = $"test-{Guid.NewGuid()}";
        Assert.Throws<HttpRequestException>(() => ShorsReplies.Get(key, () => throw new HttpRequestException("down")));
        Assert.Equal("ok", ShorsReplies.Get(key, () => "ok"));
    }
}
