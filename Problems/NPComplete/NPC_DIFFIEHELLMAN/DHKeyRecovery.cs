using System.Numerics;
using API.Problems.NPComplete.NPC_RSA;

namespace API.Problems.NPComplete.NPC_DIFFIEHELLMAN;

/// <summary>
/// The part every attack shares once it has Alice's private key a: compute the shared secret s = B^a mod p,
/// then decrypt each intercepted letter with m = c x s^-1 mod p. Each value is recorded as a step.
/// </summary>
static class DHKeyRecovery {

    /// <summary>
    /// Finishes an attack from Alice's private key, appending steps for s and each letter. Returns the answer:
    /// the key, or (key,"TEXT") in message mode, or the reason there is none.
    /// </summary>
    public static string FinishFromPrivateKey(DIFFIEHELLMAN problem, BigInteger privateKey, List<DHStep> steps) {
        BigInteger p = problem.modulus, publicB = problem.publicB;

        BigInteger s = BigInteger.ModPow(publicB, privateKey, p);
        steps.Add(new DHStep(DHStep.S, s.ToString(),
            $"Shared secret: s = B^a mod p = {publicB}^{privateKey} mod {p} (Bob computed the same value as A^b)"));

        if (!problem.isMessage)
            return problem.Answer(privateKey, Array.Empty<BigInteger>());

        BigInteger? inverse = ModularInverse(s, p);
        if (inverse is not BigInteger sInverse)
            return $"No solution: s = {s} has no inverse mod p = {p}, so the message cannot be decrypted (p is not prime)";

        var plaintexts = new List<BigInteger>();
        for (int i = 0; i < problem.ciphertexts.Count; i++) {
            BigInteger c = problem.ciphertexts[i];
            BigInteger m = c * sInverse % p;
            plaintexts.Add(m);
            steps.Add(new DHStep(DHStep.M, m.ToString(),
                $"Decrypt letter {i + 1}: c × s⁻¹ mod p = {c} × {sInverse} mod {p} = {m}, which is {LetterName(m)}", i));
        }
        return problem.Answer(privateKey, plaintexts);
    }

    /// <summary>The inverse of a modulo m by the extended Euclidean algorithm, or null if gcd(a, m) != 1.</summary>
    public static BigInteger? ModularInverse(BigInteger a, BigInteger m) {
        // Invariant: oldR = oldS * a (mod m) and r = s * a (mod m).
        BigInteger oldR = ((a % m) + m) % m, r = m, oldS = 1, s = 0;
        while (r != 0) {
            BigInteger quotient = oldR / r;
            (oldR, r) = (r, oldR - quotient * r);
            (oldS, s) = (s, oldS - quotient * s);
        }
        if (oldR != 1)
            return null;
        return ((oldS % m) + m) % m;
    }

    private static string LetterName(BigInteger code) =>
        RSAAlphabet.Decode(code) is char letter ? RSAAlphabet.Describe(letter) : "not a letter code";
}
