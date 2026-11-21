using API.Interfaces;
using API.Interfaces.JSON_Objects.Tables;
using API.Interfaces.Steps;
using API.Problems.NPComplete.NPC_RSA;
using API.Problems.NPComplete.NPC_RSA.Solvers;
using API.Problems.NPComplete.NPC_RSA.Verifiers;
using API.Problems.NPComplete.NPC_RSA.Visualizations;
using Xunit;

namespace redux_tests;

#pragma warning disable CS1591

/// <summary>
/// Tests for the Shor's algorithm solver on RSA. The quantum service is replaced by a fake that returns a fixed
/// reply, set on the solver itself (<see cref="RSAShorsQuantumSolver.CallService"/>), so these tests never touch
/// the global quantum-service settings other tests use and never need the service running. The replies are in the
/// form quantumsolver's /prime-factorization-quantum returns: {"answer": [factors], "qasm": "..."}, or an answer
/// that is a message string such as "timeout".
/// </summary>
public class RSAShorsQuantumSolver_Tests {

    private const string Lesson = "(55,3,52)";

    /// <summary>A solver whose quantum service always gives <paramref name="reply"/>, recording what was sent.</summary>
    private sealed class FakeService {
        public List<string> Requests { get; } = new();
        public RSAShorsQuantumSolver Solver { get; }

        public FakeService(string reply) : this(_ => reply) { }

        public FakeService(Func<string, string> reply) {
            Solver = new RSAShorsQuantumSolver();
            Solver.CallService = body => {
                Requests.Add(body);
                return reply(body);
            };
        }
    }

    private static string Factors(params int[] factors) =>
        $"{{\"answer\": [{string.Join(", ", factors)}], \"qasm\": \"OPENQASM 2.0;\"}}";

    private static string Message(string answer) => $"{{\"answer\": \"{answer}\", \"qasm\": \"NA\"}}";

    private static List<RSAStep> Recovered(ISolver solver, string instance) =>
        RSAStep.FromRun(solver.Run(instance, withSteps: true).Steps);

    // --- Metadata ---

    [Fact]
    public void Solver_Is_A_Quantum_Solver_Named_For_Shors_Algorithm() {
        var solver = new RSAShorsQuantumSolver();
        Assert.Equal("RSA Shor's Algorithm", solver.solverName);
        Assert.Equal(SolverType.Quantum, solver.solverType);
        Assert.Contains("computed classically", solver.solverDefinition);
        Assert.Contains("below 128", solver.solverDefinition);
    }

    // --- Solving with the service's factors ---

    [Fact]
    public void Recovers_The_Default_Message_From_The_Services_Factors() {
        var service = new FakeService(Factors(5, 11));
        var problem = new RSA();

        Assert.Equal("HELLO WORLD", service.Solver.solve(problem));
        Assert.Equal("55", Assert.Single(service.Requests));

        var steps = Recovered(service.Solver, problem.instance);
        Assert.Equal(4 + 11, steps.Count); // p, q, phi, d, then one step per letter
        Assert.Equal(new[] { "5", "11", "40", "27" }, steps.Take(4).Select(s => s.Value));
        Assert.Equal("Shor's algorithm on a quantum simulator split 55 into 5 × 11 (quantum period finding)", steps[0].HowFound);
        Assert.Equal("q = N / p = 55 / 5", steps[1].HowFound);
    }

    [Fact]
    public void Recovers_The_Lesson_Message() {
        var service = new FakeService(Factors(5, 11));
        Assert.Equal("13", service.Solver.solve(new RSA(Lesson)));
        Assert.Equal(new[] { "5", "11", "40", "27", "13" }, Recovered(service.Solver, Lesson).Select(s => s.Value));
    }

    [Fact]
    public void Takes_The_Smaller_Factor_As_P_Whatever_Order_The_Service_Uses() {
        var service = new FakeService(Factors(11, 5));
        Assert.Equal("13", service.Solver.solve(new RSA(Lesson)));
        Assert.Equal(new[] { "5", "11" }, Recovered(service.Solver, Lesson).Take(2).Select(s => s.Value));
    }

    [Theory]
    [InlineData("(55,3,52)", 5, 11)]
    [InlineData("(55,3,\"Hello World\")", 5, 11)]
    [InlineData("(119,5,32)", 7, 17)]
    [InlineData("(119,5,\"Shor\")", 7, 17)]
    public void Reads_The_Same_As_The_Factoring_Attack_From_Phi_On(string instance, int p, int q) {
        var shor = Recovered(new FakeService(Factors(p, q)).Solver, instance);
        var attack = Recovered(new RSAFactoringAttackSolver(), instance);

        Assert.Equal(attack.Select(s => (s.Variable, s.Value, s.Letter)), shor.Select(s => (s.Variable, s.Value, s.Letter)));
        Assert.Equal(attack.Skip(2).Select(s => s.HowFound), shor.Skip(2).Select(s => s.HowFound));
        Assert.NotEqual(attack[0].HowFound, shor[0].HowFound);
    }

    [Fact]
    public void An_Even_Modulus_Is_Split_By_The_Services_Classical_Check() {
        // 22 = 2 × 11: quantumsolver takes out the factor 2 before any quantum step, and the table says so.
        var service = new FakeService(Factors(2, 11));
        Assert.Equal("5", service.Solver.solve(new RSA("(22,3,15)")));
        Assert.Contains("is even, so p = 2", Recovered(service.Solver, "(22,3,15)")[0].HowFound);
    }

    [Fact]
    public void The_Answer_Passes_The_Verifier() {
        var problem = new RSA();
        string answer = new FakeService(Factors(5, 11)).Solver.solve(problem);
        Assert.True(new RSAVerifier().verify(problem, answer));
    }

    // --- Keys that are not valid RSA ---

    [Theory]
    [InlineData("(53,3,1)", new[] { 53 }, "is prime")]                                 // N prime
    [InlineData("(49,5,3)", new[] { 7, 7 }, "not a product of two distinct primes")]   // N = 7 × 7
    [InlineData("(105,11,2)", new[] { 3, 5, 7 }, "not a product of two distinct primes")]
    [InlineData("(55,5,2)", new[] { 5, 11 }, "has no inverse")]                         // gcd(5, phi = 40) = 5
    public void Reports_Keys_That_Are_Not_Valid_RSA(string instance, int[] factors, string reason) {
        string answer = new FakeService(Factors(factors)).Solver.solve(new RSA(instance));
        Assert.StartsWith("No solution", answer);
        Assert.Contains(reason, answer);
    }

    // --- When the attack cannot run ---

    [Theory]
    [InlineData("{\"answer\": \"timeout\"}", "gave up after 60 seconds")]
    [InlineData("{\"answer\": \"Input too large (limit < 10 bits)\", \"qasm\": \"NA\"}", "replied \"Input too large (limit < 10 bits)\"")]
    [InlineData("{\"answer\": \"no answer?\"}", "replied \"no answer?\"")]
    [InlineData("{\"answer\": [77], \"qasm\": \"NA\"}", "did not split N = 77")]
    [InlineData("{\"answer\": [7, 13], \"qasm\": \"NA\"}", "do not multiply to N = 77")]
    [InlineData("{\"answer\": [], \"qasm\": \"NA\"}", "returned no factors")]
    [InlineData("{\"answer\": {\"p\": 7}}", "not a list of factors")]
    [InlineData("{\"qasm\": \"NA\"}", "has no answer")]
    [InlineData("this is not JSON", "could not be read")]
    public void A_Reply_Without_Two_Factors_Is_Reported_As_Not_Run(string reply, string reason) {
        string answer = new FakeService(reply).Solver.solve(new RSA("(77,7,2)"));
        Assert.StartsWith(RecoveredValues.NotRun, answer);
        Assert.Contains(reason, answer);
    }

    [Fact]
    public void A_Service_That_Times_Out_Is_Reported_As_Not_Run() {
        var service = new FakeService(_ => throw new TimeoutException("timed out after 70 seconds"));
        string answer = service.Solver.solve(new RSA());
        Assert.StartsWith(RecoveredValues.NotRun, answer);
        Assert.Contains("did not answer within 70 seconds", answer);
    }

    [Fact]
    public void An_Unreachable_Service_Is_Reported_As_Not_Run() {
        var service = new FakeService(_ => throw new HttpRequestException("Connection refused"));
        string answer = service.Solver.solve(new RSA());
        Assert.StartsWith(RecoveredValues.NotRun, answer);
        Assert.Contains("could not reach the quantum service (Connection refused)", answer);
    }

    [Fact]
    public void Any_Other_Failure_To_Call_The_Service_Is_Reported_As_Not_Run() {
        var service = new FakeService(_ => throw new InvalidOperationException("no settings"));
        string answer = service.Solver.solve(new RSA());
        Assert.StartsWith(RecoveredValues.NotRun, answer);
        Assert.Contains("could not call the quantum service", answer);
    }

    [Theory]
    [InlineData("(128,3,5)")]
    [InlineData("(143,7,2)")]
    [InlineData("(511,5,32)")]
    [InlineData("(3233,7,1317)")]
    public void Refuses_A_Modulus_Too_Big_For_The_Simulator_Without_Calling_It(string instance) {
        var service = new FakeService(Factors(53, 61));
        string answer = service.Solver.solve(new RSA(instance));
        Assert.StartsWith(RecoveredValues.NotRun, answer);
        Assert.Contains("below 128", answer);
        Assert.Empty(service.Requests);
    }

    [Fact]
    public void Accepts_A_Seven_Bit_Modulus() {
        // 119 = 7 × 17, one of the largest RSA moduli under 128 (127 itself is prime).
        var service = new FakeService(Factors(7, 17));
        Assert.Equal("2", service.Solver.solve(new RSA("(119,5,32)")));
        Assert.Equal("119", Assert.Single(service.Requests));
    }

    [Fact]
    public void Stops_Without_Calling_The_Service_When_The_Timer_Has_Expired() {
        var service = new FakeService(Factors(5, 11));
        service.Solver.timerHasExpired = true;
        Assert.Equal(RSAShorsQuantumSolver.Timeout, service.Solver.solve(new RSA()));
        Assert.Empty(service.Requests);
    }

    // --- Recorded steps ---

    [Fact]
    public void A_Run_That_Could_Not_Run_Ends_With_A_Failed_Done_Step() {
        var service = new FakeService(Message("timeout"));
        var steps = ((ISolver)service.Solver).Run(Lesson, withSteps: true).Steps.OfType<SolverStep<Assignment>>().ToList();

        var done = Assert.Single(steps);
        Assert.Equal(StepEvent.Done, done.Event);
        Assert.False(done.Ok);
    }

    [Fact]
    public void A_Successful_Run_Ends_With_A_Successful_Done_Step() {
        var service = new FakeService(Factors(5, 11));
        var done = ((ISolver)service.Solver).Run(Lesson, withSteps: true).Steps.OfType<SolverStep<Assignment>>().Last();
        Assert.Equal(StepEvent.Done, done.Event);
        Assert.True(done.Ok);
    }

    // --- Visualization ---

    private static List<API_TableJSON> Frames(RSA problem, ISolver solver) =>
        new RSAKnowledgeTableVisualization()
            .StepsVisualization(problem, solver.GetSteps(problem.instance))
            .Cast<API_TableJSON>().ToList();

    [Fact]
    public void Knowledge_Table_Matches_The_Factoring_Attack_Except_How_P_And_Q_Were_Found() {
        var problem = new RSA();
        var shor = Frames(problem, new FakeService(Factors(5, 11)).Solver);
        var attack = Frames(problem, new RSAFactoringAttackSolver());

        Assert.Equal(attack.Count, shor.Count);
        for (int i = 0; i < shor.Count; i++) {
            Assert.Equal(attack[i].title, shor[i].title);
            Assert.Equal(attack[i].rows.Select(r => r.id), shor[i].rows.Select(r => r.id));
            foreach (var row in shor[i].rows) {
                var other = attack[i].rows.Single(r => r.id == row.id);
                Assert.Equal(other.color, row.color);
                Assert.Equal(other.cells["value"], row.cells["value"]);
                if (row.id is not (RSAStep.P or RSAStep.Q))
                    Assert.Equal(other.cells, row.cells);
            }
        }
        Assert.Contains(shor[^1].rows.Single(r => r.id == RSAStep.P).cells.Values,
            text => text.Contains("Shor's algorithm on a quantum simulator", StringComparison.Ordinal));
    }
}
