using System.Numerics;

namespace API.Problems.NPComplete.NPC_RSA;

/// <summary>
/// How a message becomes numbers for RSA in message mode: A = 1 ... Z = 26 (the common textbook scheme)
/// and space = 27. Lower-case letters encode like their capitals, so recovered text is upper case.
///
/// Each letter is encrypted on its own, so repeated letters give repeated ciphertexts, and A = 1 always
/// encrypts to 1 (1^e = 1). Both are real weaknesses of letter-by-letter RSA and worth pointing out.
/// </summary>
static class RSAAlphabet {

    public const int Space = 27;

    /// <summary>The largest code; the modulus must be bigger than this for every code to be a valid message.</summary>
    public const int LargestCode = Space;

    public static bool IsEncodable(char ch) => ch == ' ' || ch is >= 'A' and <= 'Z' || ch is >= 'a' and <= 'z';

    public static int Encode(char ch) => ch == ' ' ? Space : char.ToUpperInvariant(ch) - 'A' + 1;

    /// <summary>The letter a code stands for, or null if the code is not a letter or space.</summary>
    public static char? Decode(BigInteger code) {
        if (code == Space)
            return ' ';
        if (code >= 1 && code <= 26)
            return (char)('A' + (int)code - 1);
        return null;
    }

    /// <summary>A letter as it should read in an explanation, so a space is visible.</summary>
    public static string Describe(char ch) => ch == ' ' ? "space" : ch.ToString();
}
