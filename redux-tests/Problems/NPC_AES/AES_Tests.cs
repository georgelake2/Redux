using System.Security.Cryptography;
using API.Interfaces;
using API.Interfaces.JSON_Objects.Tables;
using API.Problems.NPComplete.NPC_AES;
using API.Problems.NPComplete.NPC_AES.Solvers;
using API.Problems.NPComplete.NPC_AES.Verifiers;
using API.Problems.NPComplete.NPC_AES.Visualizations;
using Xunit;
using DotNetAes = System.Security.Cryptography.Aes;

namespace redux_tests;

#pragma warning disable CS1591

/// <summary>
/// AES problem tests. The cipher is checked against FIPS 197 (Appendix A.1 key expansion, Appendix B round by round,
/// Appendix C.1), NIST ACVP AES-128 ECB vectors and .NET's own AES. Expected search results and message-mode
/// ciphertexts were computed independently with the thesis Phase 0 reference implementation.
/// </summary>
public class AES_Tests {
    // The values a solver's run recovered, read back from its typed steps.
    private static List<AESStep> Recovered(ISolver solver, string instance) =>
        AESStep.FromRun(solver.Run(instance, withSteps: true).Steps);


    private const string FipsKey = "2b7e151628aed2a6abf7158809cf4f3c";
    private const string FipsPlaintext = "3243f6a8885a308d313198a2e0370734";
    private const string FipsCiphertext = "3925841d02dc09fbdc118597196a0b32";

    // FIPS 197 Appendix B as Eve's view: the last 8 bits (3c) unknown.
    private const string FipsEveView = $"(2b7e151628aed2a6abf7158809cf4f00,8,{FipsPlaintext},{FipsCiphertext})";

    // The default instance's ciphertext: "HELLO WORLD" plus 5 padding bytes under the FIPS key.
    private const string HelloWorldCiphertext = "2a68e62d3495189e97079d6c9b5f852a";

    private static byte[] Bytes(string hex) => Convert.FromHexString(hex);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // --- The cipher ---

    [Fact]
    public void SBox_Matches_FIPS197() {
        Assert.Equal(0x63, AESCipher.SBox[0x00]);
        Assert.Equal(0xed, AESCipher.SBox[0x53]); // FIPS 197 Section 5.1.1 example
        Assert.Equal(0x16, AESCipher.SBox[0xff]);
        Assert.Equal(256, AESCipher.SBox.Distinct().Count());
    }

    [Fact]
    public void GF_Multiply_Matches_FIPS197() {
        Assert.Equal(0xc1, AESCipher.Multiply(0x57, 0x83)); // Section 4.2
        Assert.Equal(0xfe, AESCipher.Multiply(0x57, 0x13)); // Section 4.2.1
    }

    [Fact]
    public void Key_Expansion_Matches_FIPS197_Appendix_A1() {
        byte[][] roundKeys = AESCipher.ExpandKey(Bytes(FipsKey));
        Assert.Equal(11, roundKeys.Length);
        Assert.Equal(FipsKey, Hex(roundKeys[0]));
        Assert.Equal("a0fafe1788542cb123a339392a6c7605", Hex(roundKeys[1]));
        Assert.Equal("d014f9a8c9ee2589e13f0cc8b6630ca6", Hex(roundKeys[10]));
    }

    [Theory]
    [InlineData(FipsKey, FipsPlaintext, FipsCiphertext)]                                                   // Appendix B
    [InlineData("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a")] // Appendix C.1
    // NIST ACVP AES-ECB-1.0 AES-128 known-answer tests (tcId 1, 8, 29, 157, 1040, 1047, 1196, 2109).
    [InlineData("00000000000000000000000000000000", "b26aeb1874e47ca8358ff22378f09144", "459264f4798f6a78bacb89c15ed3d601")]
    [InlineData("64110a924f0743d500ccadae72c13427", "00000000000000000000000000000000", "35870c6a57e9e92314bcb8087cde72ce")]
    [InlineData("00000000000000000000000000000000", "80000000000000000000000000000000", "3ad78e726c1ec02b7ebfe92b23d9ec34")]
    [InlineData("fffffffff80000000000000000000000", "00000000000000000000000000000000", "0f18aff94274696d9b61848bd50ac5e5")]
    [InlineData("00000000000000000000000000000000", "f34481ec3cc627bacd5dc3fb08f273e6", "0336763e966d92595a567cc9ce537f5e")]
    [InlineData("10a58869d74be5a374cf867cfb473859", "00000000000000000000000000000000", "6d251e6944b051e04eaa6fb4dbf78465")]
    [InlineData("f0000000000000000000000000000000", "00000000000000000000000000000000", "970014d634e2b7650777e8e84d03ccd8")]
    [InlineData("77115e341662e6922cd3ba91911bae04", "711666dd4cd0b641d1199efc92072430", "961f0435afb1a6965d07287c41d0079c")]
    public void Cipher_Matches_FIPS197_And_NIST_Vectors(string key, string plaintext, string ciphertext) {
        Assert.Equal(ciphertext, Hex(AESCipher.Encrypt(Bytes(plaintext), Bytes(key))));
        Assert.Equal(plaintext, Hex(AESCipher.Decrypt(Bytes(ciphertext), Bytes(key))));
    }

    [Fact]
    public void Cipher_Matches_DotNet_AES_On_Random_Blocks() {
        var random = new Random(6650);
        using var reference = DotNetAes.Create();
        for (int i = 0; i < 200; i++) {
            byte[] key = new byte[16], block = new byte[16];
            random.NextBytes(key);
            random.NextBytes(block);
            reference.Key = key;
            Assert.Equal(reference.EncryptEcb(block, PaddingMode.None), AESCipher.Encrypt(block, key));
            Assert.Equal(block, AESCipher.Decrypt(AESCipher.Encrypt(block, key), key));
        }
    }

    [Fact]
    public void Trace_Matches_FIPS197_Appendix_B_Round_By_Round() {
        List<AESRoundState> trace = AESCipher.EncryptWithTrace(Bytes(FipsPlaintext), Bytes(FipsKey));
        Assert.Equal(41, trace.Count); // input, initial AddRoundKey, 9 x 4 operations, then 3 in round 10
        Assert.Equal((AESCipher.Input, FipsPlaintext), (trace[0].Operation, Hex(trace[0].State)));
        Assert.Equal("193de3bea0f4e22b9ac68d2ae9f84808", Hex(trace[1].State));   // after the initial AddRoundKey
        Assert.Equal("d42711aee0bf98f1b8b45de51e415230", Hex(trace[2].State));   // round 1 SubBytes
        Assert.Equal("d4bf5d30e0b452aeb84111f11e2798e5", Hex(trace[3].State));   // round 1 ShiftRows
        Assert.Equal("046681e5e0cb199a48f8d37a2806264c", Hex(trace[4].State));   // round 1 MixColumns
        Assert.Equal("a49c7ff2689f352b6b5bea43026a5049", Hex(trace[5].State));   // round 1 AddRoundKey
        Assert.DoesNotContain(trace, s => s.Round == 10 && s.Operation == AESCipher.MixColumnsStep);
        Assert.Equal(FipsCiphertext, Hex(trace[^1].State));
        Assert.Equal("d014f9a8c9ee2589e13f0cc8b6630ca6", Hex(trace[^1].RoundKey!));
    }

    // --- Messages and padding ---

    [Fact]
    public void Message_Is_Uppercased_And_Padded_To_One_Block() {
        Assert.Equal("48454c4c4f20574f524c440505050505", Hex(AESMessage.Pad("Hello World")));
        Assert.Equal("HELLO WORLD", AESMessage.Read(AESMessage.Pad("Hello World")));
        Assert.Equal("ABCDEFGHIJKLMNO", AESMessage.Read(AESMessage.Pad("abcdefghijklmno"))); // 15 letters, 1 padding byte
    }

    [Theory]
    [InlineData("48454c4c4f20574f524c440505050504")] // padding bytes disagree
    [InlineData("48454c4c4f20574f524c440505050500")] // padding 0
    [InlineData("10101010101010101010101010101010")] // a whole block of padding: no message
    [InlineData("68454c4c4f20574f524c440505050505")] // lower-case h: never produced by the encoder
    [InlineData(FipsCiphertext)]                     // random-looking bytes
    public void Read_Rejects_Blocks_That_Are_Not_A_Message(string block) {
        Assert.Null(AESMessage.Read(Bytes(block)));
    }

    // --- Instance parsing ---

    [Fact]
    public void AES_Default_Instance_Is_A_Message() {
        var problem = new AES();
        Assert.Equal("(2b7e151628aed2a6abf7158809cf4f3c,8,\"Hello World\")", problem.instance);
        Assert.True(problem.isMessage);
        Assert.Null(problem.knownPlaintext);
        Assert.Equal(8, problem.unknownBits);
        Assert.Equal(256, problem.candidateCount);
        Assert.Equal("2b7e151628aed2a6abf7158809cf4f00", Hex(problem.knownKey)); // the key itself is not kept
        Assert.Equal(HelloWorldCiphertext, Hex(problem.ciphertext));
        Assert.Equal("2b7e151628aed2a6abf7158809cf4f??", problem.KnownKeyText());
    }

    [Fact]
    public void AES_Eve_View_Instance_Keeps_What_Eve_Sees() {
        var problem = new AES(FipsEveView);
        Assert.False(problem.isMessage);
        Assert.Equal(FipsPlaintext, Hex(problem.knownPlaintext!));
        Assert.Equal(FipsCiphertext, Hex(problem.ciphertext));
    }

    [Theory]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"HELLO WORLD\")")]
    [InlineData("( 2B7E151628AED2A6ABF7158809CF4F3C , 8 , \"hello world\" )")]
    public void AES_Message_Ignores_Case_And_Spacing_Around_Values(string instance) {
        Assert.Equal(new AES().ciphertext, new AES(instance).ciphertext);
    }

    [Fact]
    public void Known_Key_Text_Hides_Every_Hex_Digit_With_An_Unknown_Bit() {
        var problem = new AES("(2b7e151628aed2a6abf7158809cf4c00,10,3243f6a8885a308d313198a2e0370734,3925841d02dc09fbdc118597196a0b32)");
        Assert.Equal("2b7e151628aed2a6abf7158809cf4???", problem.KnownKeyText()); // 10 bits touch 3 hex digits
        Assert.Equal("33c (binary 1100111100)", problem.MissingBitsText(828));
    }

    [Theory]
    [InlineData("")]
    [InlineData("2b7e151628aed2a6abf7158809cf4f3c,8,\"HI\"")]                // no parentheses
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8)")]                     // too few values
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,HI)")]                  // message without quotes
    [InlineData("(2b7e151628aed2a6abf7158809cf4f,8,\"HI\")")]                // key too short
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3g,8,\"HI\")")]              // not hex
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,0,\"HI\")")]              // k < 1
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,21,\"HI\")")]             // k > 20
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,x,\"HI\")")]              // k not a number
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"\")")]                // empty message
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"HI)")]                // unclosed quote
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"H1\")")]              // digit in the message
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"HI, YOU\")")]         // punctuation in the message
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"SIXTEEN CHARS OK\")")] // 16 characters need a second block
    [InlineData(FipsEveViewWithKnownBitsSet)]                                // Eve's view must zero the unknown bits
    [InlineData("(2b7e151628aed2a6abf7158809cf4f00,8,3243f6a8885a308d313198a2e0370734)")] // Eve's view missing the ciphertext
    public void AES_Rejects_Malformed_Or_Out_Of_Range_Instances(string instance) {
        Assert.Throws<ProblemParseException>(() => new AES(instance));
    }

    [Fact]
    public void AES_Accepts_A_Message_That_Just_Fits_In_One_Block() {
        Assert.True(new AES("(2b7e151628aed2a6abf7158809cf4f3c,8,\"FIFTEEN LETTERS\")").isMessage); // 15 characters
    }

    private const string FipsEveViewWithKnownBitsSet = $"({FipsKey},8,{FipsPlaintext},{FipsCiphertext})";

    // --- The attack ---

    [Fact]
    public void BruteForce_Recovers_The_Default_Message() {
        var solver = new AESBruteForceKeySearchSolver();
        Assert.Equal("(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLD\")", solver.solve(new AES()));
        var steps = Recovered(solver, new AES().instance);
        Assert.Equal(new[] { AESStep.Bits, AESStep.Key, AESStep.M }, steps.Select(s => s.Variable));
        Assert.Equal("3c (binary 00111100)", steps[0].Value);
        Assert.Contains("on try 61 of 256", steps[0].HowFound); // 0x3c = 60, counting from 0
        Assert.Equal(FipsKey, steps[1].Value);
        Assert.Equal("\"HELLO WORLD\"", steps[2].Value);
        Assert.Contains("5 padding bytes", steps[2].HowFound);
    }

    [Fact]
    public void BruteForce_Recovers_The_FIPS197_Key_From_A_Known_Plaintext() {
        var solver = new AESBruteForceKeySearchSolver();
        Assert.Equal(FipsKey, solver.solve(new AES(FipsEveView)));
        Assert.Equal(new[] { AESStep.Bits, AESStep.Key }, Recovered(solver, FipsEveView).Select(s => s.Variable));
    }

    [Theory]
    [InlineData("(2b7e151628aed2a6abf7158809cf4c00,10,3243f6a8885a308d313198a2e0370734,3925841d02dc09fbdc118597196a0b32)",
        "2b7e151628aed2a6abf7158809cf4f3c", "on try 829 of 1024")]                         // k not a multiple of 4
    [InlineData("(00000000000000000000000000000000,20,b26aeb1874e47ca8358ff22378f09144,459264f4798f6a78bacb89c15ed3d601)",
        "00000000000000000000000000000000", "on try 1 of 1048576")]                        // NIST tcId 1, largest k
    [InlineData("(000102030405060708090a0b0c0d0e0f,12,\"Grover\")",
        "(000102030405060708090a0b0c0d0e0f,\"GROVER\")", "on try 3600 of 4096")]          // message, k = 12
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"hi there\")",
        "(2b7e151628aed2a6abf7158809cf4f3c,\"HI THERE\")", "on try 61 of 256")]
    public void BruteForce_Finds_The_Missing_Bits(string instance, string answer, string tries) {
        var solver = new AESBruteForceKeySearchSolver();
        Assert.Equal(answer, solver.solve(new AES(instance)));
        Assert.Contains(tries, Recovered(solver, instance).First().HowFound);
    }

    [Fact]
    public void BruteForce_Reports_When_No_Key_Fits() {
        // The FIPS ciphertext with its last byte changed: no candidate encrypts the plaintext to it.
        string answer = new AESBruteForceKeySearchSolver().solve(
            new AES($"(2b7e151628aed2a6abf7158809cf4f00,8,{FipsPlaintext},3925841d02dc09fbdc118597196a0b33)"));
        Assert.StartsWith("No solution", answer);
        Assert.Contains("all 256 tried", answer);
        Assert.Empty(Recovered(new AESBruteForceKeySearchSolver(),
            $"(2b7e151628aed2a6abf7158809cf4f00,8,{FipsPlaintext},3925841d02dc09fbdc118597196a0b33)"));
    }

    [Fact]
    public void Solver_Stops_When_The_Timer_Expires() {
        Assert.Equal(AESBruteForceKeySearchSolver.Timeout,
            new AESBruteForceKeySearchSolver { timerHasExpired = true }.solve(new AES()));
    }

    // --- Verifier ---

    [Theory]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLD\")", true)]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,\"hello world\")", true)]
    [InlineData(" ( 2B7E151628AED2A6ABF7158809CF4F3C , \"HELLO WORLD\" ) ", true)]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,HELLO WORLD)", true)]          // quotes are optional
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3d,\"HELLO WORLD\")", false)]     // wrong missing bits
    [InlineData("(3b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLD\")", false)]     // disagrees with a known bit
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLE\")", false)]     // right key, wrong message
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO\")", false)]           // too short
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,\"HELLO WORLD HELLO\")", false)] // too long for one block
    public void Verifier_Checks_The_Key_And_The_Message(string certificate, bool expected) {
        Assert.Equal(expected, new AESVerifier().verify(new AES(), certificate));
    }

    [Theory]
    [InlineData(FipsKey, true)]
    [InlineData(" 2B7E151628AED2A6ABF7158809CF4F3C ", true)]
    [InlineData("2b7e151628aed2a6abf7158809cf4f3d", false)]
    [InlineData("2b7e151628aed2a6abf7158809cf4e3c", false)] // a known bit changed
    public void Verifier_Checks_The_Key_In_Eve_View(string certificate, bool expected) {
        Assert.Equal(expected, new AESVerifier().verify(new AES(FipsEveView), certificate));
    }

    [Fact]
    public void Verifier_Accepts_The_Advertised_Example_For_The_Default_Instance() {
        Assert.True(new AESVerifier().verify(new AES(), AESVerifier.CertificateExample));
    }

    [Fact]
    public void Verifier_Accepts_Every_Answer_The_Solver_Gives() {
        foreach (string instance in new[] { new AES().instance, FipsEveView, "(000102030405060708090a0b0c0d0e0f,12,\"Grover\")" }) {
            var problem = new AES(instance);
            Assert.True(new AESVerifier().verify(problem, new AESBruteForceKeySearchSolver().solve(problem)), instance);
        }
    }

    [Theory]
    [InlineData(FipsEveView, "2b7e")]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"Hello World\")", FipsKey)]                      // a message needs the key and the message
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"Hello World\")", "(xyz,\"HELLO WORLD\")")]
    [InlineData("(2b7e151628aed2a6abf7158809cf4f3c,8,\"Hello World\")", $"({FipsKey},\"HELL0 WORLD\")")]
    public void Verifier_Rejects_A_Certificate_It_Cannot_Read(string instance, string certificate) {
        Assert.Throws<CertificateParseException>(() => new AESVerifier().verify(new AES(instance), certificate));
    }

    // --- Knowledge table ---

    private static List<API_TableJSON> KnowledgeFrames(AES problem) =>
        new AESKnowledgeTableVisualization()
            .StepsVisualization(problem, ((ISolver)new AESBruteForceKeySearchSolver()).GetSteps(problem.instance))
            .Cast<API_TableJSON>().ToList();

    private static TableRow Row(API_TableJSON table, string id) => table.rows.Single(r => r.id == id);

    [Fact]
    public void Knowledge_Table_Starts_With_Only_What_Eve_Sees() {
        var message = new AESKnowledgeTableVisualization().visualize(new AES());
        Assert.Equal(new[] { "known", "k", "ct", "bits", "key", "m" }, message.rows.Select(r => r.id));
        Assert.Equal("2b7e151628aed2a6abf7158809cf4f??", Row(message, "known").cells["value"]);
        Assert.Equal("8, so 2^8 = 256 candidate keys", Row(message, "k").cells["value"]);
        Assert.Equal(HelloWorldCiphertext, Row(message, "ct").cells["value"]);
        Assert.All(AESStep.Secrets, secret => Assert.Equal("?", Row(message, secret).cells["value"]));

        var eveView = new AESKnowledgeTableVisualization().visualize(new AES(FipsEveView));
        Assert.Equal(new[] { "known", "k", "pt", "ct", "bits", "key" }, eveView.rows.Select(r => r.id));
    }

    [Fact]
    public void Knowledge_Table_Fills_In_The_Bits_Then_The_Key_Then_The_Message() {
        var frames = KnowledgeFrames(new AES());
        Assert.Equal(3, frames.Count);

        Assert.Equal("Step 1 of 3: found the missing key bits", frames[0].title);
        Assert.Equal("3c (binary 00111100)", Row(frames[0], "bits").cells["value"]);
        Assert.Equal("ElementHighlight", Row(frames[0], "bits").color);
        Assert.Equal("?", Row(frames[0], "key").cells["value"]);

        Assert.Equal(FipsKey, Row(frames[1], "key").cells["value"]);
        Assert.Null(Row(frames[1], "bits").color);

        Assert.Equal("\"HELLO WORLD\"", Row(frames[2], "m").cells["value"]);
        Assert.Equal("Solution", Row(frames[2], "m").color);
        Assert.Equal("No, but recovered", Row(frames[2], "m").cells["visibility"]);
    }

    [Fact]
    public void Knowledge_Table_Marks_The_Key_As_The_Result_In_Eve_View() {
        var frames = KnowledgeFrames(new AES(FipsEveView));
        Assert.Equal(2, frames.Count);
        Assert.Equal("Solution", Row(frames[^1], "key").color);
    }

    // --- Round-by-round grid ---

    private static List<API_TableJSON> RoundFrames(AES problem) =>
        new AESRoundVisualization()
            .StepsVisualization(problem, ((ISolver)new AESBruteForceKeySearchSolver()).GetSteps(problem.instance))
            .Cast<API_TableJSON>().ToList();

    /// <summary>The 16 bytes of a grid, read column by column as FIPS 197 does.</summary>
    private static string GridHex(API_TableJSON grid) =>
        string.Concat(Enumerable.Range(0, 4).SelectMany(c => Enumerable.Range(0, 4).Select(r => Row(grid, $"r{r}").cells[$"c{c}"])));

    [Fact]
    public void Round_Grid_Starts_With_The_Ciphertext_Alone() {
        var grid = new AESRoundVisualization().visualize(new AES());
        Assert.Equal(HelloWorldCiphertext, GridHex(grid));
        Assert.Equal(new[] { "row", "c0", "c1", "c2", "c3" }, grid.columns.Select(c => c.key));
    }

    [Fact]
    public void Round_Grid_Replays_Alices_Encryption_Of_The_Message() {
        var frames = RoundFrames(new AES());
        Assert.Equal(41, frames.Count);
        Assert.Equal("48454c4c4f20574f524c440505050505", GridHex(frames[0])); // "HELLO WORLD" and 5 padding bytes
        Assert.Equal("48", Row(frames[0], "r0").cells["c0"]);              // H, row 0 of column 0
        Assert.Equal("4f", Row(frames[0], "r0").cells["c1"]);              // O, byte 4 starts column 1
        Assert.StartsWith("Step 1 of 41: Alice's message", frames[0].title);
        Assert.Equal("fbe2cbbe8519971e99ead15dfe74d612", GridHex(frames[2])); // round 1 SubBytes
        Assert.Equal(HelloWorldCiphertext, GridHex(frames[^1]));
        Assert.EndsWith("= the intercepted ciphertext", frames[^1].title);
        Assert.All(frames[^1].rows, row => Assert.Equal("Solution", row.color));
    }

    [Fact]
    public void Round_Grid_Matches_FIPS197_Appendix_B_And_Highlights_Changed_Bytes() {
        var frames = RoundFrames(new AES(FipsEveView));
        Assert.Equal(FipsPlaintext, GridHex(frames[0]));
        Assert.Equal("d4bf5d30e0b452aeb84111f11e2798e5", GridHex(frames[3]));
        Assert.Equal("Step 4 of 41: Round 1 of 10, ShiftRows: row i shifted i places to the left", frames[3].title);
        Assert.Contains("round key 0 (2b7e151628aed2a6abf7158809cf4f3c, the key itself)", frames[1].title);

        // ShiftRows never moves row 0, and moves every byte of rows 1 to 3 here.
        Assert.Null(Row(frames[3], "r0").cellColors);
        Assert.Equal(4, Row(frames[3], "r1").cellColors!.Count);
        Assert.Null(Row(frames[0], "r0").cellColors); // nothing to compare the input with
    }

    [Fact]
    public void Round_Grid_Has_No_Steps_When_No_Key_Was_Found() {
        var problem = new AES($"(2b7e151628aed2a6abf7158809cf4f00,8,{FipsPlaintext},3925841d02dc09fbdc118597196a0b33)");
        Assert.Empty(RoundFrames(problem));
    }
}
