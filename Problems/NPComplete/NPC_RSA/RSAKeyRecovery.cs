using System.Numerics;

namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// What every factoring-based attack on RSA does once it knows p and q: rebuild the private key exactly the way
/// its owner made it (phi, then d), and decrypt. The classical factoring attack and Shor's algorithm differ only
/// in how they find p and q, so both finish here, and their runs read the same from phi onwards.
/// </summary>
static class RSAKeyRecovery {

    /// <summary>
    /// Adds a step for phi, for d and for each decrypted ciphertext to <paramref name="steps"/>, and returns the
    /// answer: the plaintext, or the reason there is none.
    /// </summary>
    public static string Finish(RSA problem, BigInteger p, BigInteger q, List<RSAStep> steps) {
        BigInteger n = problem.modulus, e = problem.publicExponent;

        // Euler's totient, which only someone who knows p and q can compute.
        BigInteger phi = (p - 1) * (q - 1);
        steps.Add(new RSAStep(RSAStep.Phi, phi.ToString(), $"φ = (p - 1)(q - 1) = {p - 1} × {q - 1}"));

        // The private exponent: the inverse of e modulo phi.
        BigInteger? inverse = ModularInverse(e, phi);
        if (inverse is not BigInteger d)
            return $"No solution: e = {e} has no inverse mod φ = {phi}, so there is no private key";
        steps.Add(new RSAStep(RSAStep.D, d.ToString(),
            $"Extended Euclid: d = e⁻¹ mod φ, since {e} × {d} = {e * d} ≡ 1 (mod {phi})"));

        // Decrypt every ciphertext with the recovered key, one step each.
        var plaintexts = new List<BigInteger>();
        for (int i = 0; i < problem.ciphertexts.Count; i++) {
            BigInteger c = problem.ciphertexts[i];
            BigInteger m = BigInteger.ModPow(c, d, n);
            plaintexts.Add(m);
            steps.Add(problem.isMessage
                ? new RSAStep(RSAStep.M, m.ToString(),
                    $"Decrypt letter {i + 1}: {c}^{d} mod {n} = {m}, which is {LetterName(m)}", i)
                : new RSAStep(RSAStep.M, m.ToString(), $"Decrypt: m = c^d mod N = {c}^{d} mod {n}"));
        }
        return problem.Answer(plaintexts);
    }

    private static string LetterName(BigInteger code) =>
        RSAAlphabet.Decode(code) is char letter ? RSAAlphabet.Describe(letter) : "not a letter code";

    /// <summary>The inverse of a modulo m by the extended Euclidean algorithm, or null if gcd(a, m) != 1.</summary>
    private static BigInteger? ModularInverse(BigInteger a, BigInteger m) {
        // Invariant: oldR = oldS * a (mod m) and r = s * a (mod m).
        BigInteger oldR = a % m, r = m, oldS = 1, s = 0;
        while (r != 0) {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
        }
        if (oldR != 1)
            return null;
        return ((oldS % m) + m) % m;
    }
}
