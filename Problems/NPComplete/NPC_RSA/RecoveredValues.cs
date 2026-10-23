using API.Interfaces.Steps;

namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// Records a crypto attack's run as typed solver steps and reads them back. Each value the attack recovers is one
/// Accept step: its focus is the value's name, its caption says how the attack found it, and its partial answer
/// holds every value found so far (an <see cref="Assignment"/> from name to value). Done closes the run with every
/// value found plus the answer itself, under <see cref="AnswerName"/>. The RSA, Diffie-Hellman and AES attacks all
/// record this way, so each knowledge table can replay any of its problem's solvers.
/// </summary>
static class RecoveredValues {

    /// <summary>The name the Done step's partial answer gives the solver's answer.</summary>
    public const string AnswerName = "answer";

    /// <summary>
    /// Records a finished attack: one Accept step per value in <paramref name="found"/>, in order, then Done. The
    /// attacks run fast and find only a few values, so they record after the run rather than during it.
    /// </summary>
    public static void Record(StepRecorder<Assignment> rec, IReadOnlyList<(string Name, string Value, string HowFound)> found,
            string answer, string timeout) {
        for (int i = 0; i < found.Count; i++) {
            int upTo = i + 1;
            var (name, _, howFound) = found[i];
            rec.Accept(() => Known(found.Take(upTo)), () => howFound, name);
        }
        bool ok = answer != timeout && !answer.StartsWith("No solution", StringComparison.Ordinal);
        var all = Known(found).Values.Append(new KeyValuePair<string, string>(AnswerName, answer));
        rec.Done(new Assignment(all), ok, ok ? $"Recovered the answer: {answer}" : answer);
    }

    /// <summary>The values a run recovered, in order, read back from its Accept steps (Done is left out).</summary>
    public static IEnumerable<(string Name, string Value, string HowFound)> Read(IEnumerable<object> steps) =>
        steps.OfType<SolverStep<Assignment>>()
            .Where(s => s.Event == StepEvent.Accept)
            .Select(s => (s.Focus[0], s.Partial.Values[s.Focus[0]], s.Caption));

    private static Assignment Known(IEnumerable<(string Name, string Value, string HowFound)> found) =>
        new(found.Select(v => new KeyValuePair<string, string>(v.Name, v.Value)));
}
