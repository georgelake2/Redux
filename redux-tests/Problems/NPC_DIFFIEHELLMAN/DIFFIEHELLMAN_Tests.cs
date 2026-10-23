using System.Globalization;
using System.Numerics;
using API.Interfaces;
using API.Interfaces.JSON_Objects.Tables;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Solvers;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Verifiers;
using API.Problems.NPComplete.NPC_DIFFIEHELLMAN.Visualizations;
using Xunit;

namespace redux_tests;

#pragma warning disable CS1591

/// <summary>
/// Diffie-Hellman problem tests. Known answers come from the thesis Phase 0 reference implementation's toy
/// groups (p = 23, 47, 59) and from NIST ACVP SP 800-56A Rev. 3 finite-field DH vectors (2048-bit groups).
/// Expected message-mode ciphertexts were computed independently (A = 1 ... Z = 26, space = 27; c = code x s mod p).
/// </summary>
public class DIFFIEHELLMAN_Tests {
    // The values a solver's run recovered, read back from its typed steps.
    private static List<DHStep> Recovered(ISolver solver, string instance) =>
        DHStep.FromRun(solver.Run(instance, withSteps: true).Steps);


    private const string Toy = "(23,5,4,10)"; // Phase 0: a = 4, b = 3, shared secret 18

    // "HELLO WORLD" with p = 59, g = 2, a = 13, b = 23: shared secret 40, each letter's code times 40 mod 59.
    private static readonly int[] HelloWorldCiphertexts = { 25, 23, 8, 8, 10, 18, 35, 10, 12, 8, 42 };

    private static readonly ISolver[] BothSolvers = { new DHBruteForceDiscreteLogSolver(), new DHBabyStepGiantStepSolver() };

    // --- Instance parsing ---

    [Fact]
    public void DH_Default_Instance_Is_A_Message() {
        var problem = new DIFFIEHELLMAN();
        Assert.Equal("(59,2,13,23,\"Hello World\")", problem.instance);
        Assert.True(problem.isMessage);
        Assert.Equal(new BigInteger(59), problem.modulus);
        Assert.Equal(new BigInteger(2), problem.generator);
        Assert.Equal(new BigInteger(50), problem.publicA); // 2^13 mod 59
        Assert.Equal(new BigInteger(47), problem.publicB); // 2^23 mod 59
        Assert.Equal(HelloWorldCiphertexts.Select(c => new BigInteger(c)), problem.ciphertexts);
    }

    [Fact]
    public void DH_Eve_View_Instance_Keeps_The_Public_Values() {
        var problem = new DIFFIEHELLMAN(Toy);
        Assert.False(problem.isMessage);
        Assert.Empty(problem.ciphertexts);
        Assert.Equal((new BigInteger(23), new BigInteger(5), new BigInteger(4), new BigInteger(10)),
            (problem.modulus, problem.generator, problem.publicA, problem.publicB));
    }

    [Theory]
    [InlineData("(59,2,13,23,\"hello world\")")]
    [InlineData("( 59 , 2 , 13 , 23 , \"HELLO WORLD\" )")]
    public void DH_Message_Ignores_Case_And_Spacing_Around_Values(string instance) {
        Assert.Equal(new DIFFIEHELLMAN().ciphertexts, new DIFFIEHELLMAN(instance).ciphertexts);
    }

    [Theory]
    [InlineData("")]
    [InlineData("(23,5,4)")]
    [InlineData("23,5,4,10")]
    [InlineData("(23,5,x,10)")]
    [InlineData("(2,1,1,1)")]                    // p < 3
    [InlineData("(23,1,4,10)")]                  // g <= 1
    [InlineData("(23,23,4,10)")]                 // g >= p
    [InlineData("(23,5,0,10)")]                  // A < 1
    [InlineData("(23,5,4,23)")]                  // B >= p
    [InlineData("(23,5,4,10,11)")]               // fifth value is not a quoted message
    [InlineData("(59,2,0,23,\"HI\")")]           // a < 1
    [InlineData("(59,2,13,58,\"HI\")")]          // b > p - 2
    [InlineData("(59,2,13,23,\"\")")]            // empty message
    [InlineData("(59,2,13,23,\"HI)")]            // unclosed quote
    [InlineData("(59,2,13,23,\"H1\")")]          // digit in the message
    [InlineData("(59,2,13,23,\"HI, YOU\")")]     // punctuation in the message
    [InlineData("(23,5,4,3,\"HI\")")]            // p too small for letter codes up to 27
    public void DH_Rejects_Malformed_Or_Out_Of_Range_Instances(string instance) {
        Assert.Throws<ProblemParseException>(() => new DIFFIEHELLMAN(instance));
    }

    // --- Both attacks ---

    [Fact]
    public void Both_Solvers_Recover_The_Default_Message() {
        foreach (ISolver solver in BothSolvers) {
            Assert.Equal("(13,\"HELLO WORLD\")", solver.solve(new DIFFIEHELLMAN().instance));
            var steps = Recovered(solver, new DIFFIEHELLMAN().instance);
            Assert.Equal(2 + 11, steps.Count); // a, s, then one step per letter
            Assert.Equal(new[] { "13", "40" }, steps.Take(2).Select(s => s.Value));
            Assert.Equal(new[] { "8", "5", "12", "12", "15", "27", "23", "15", "18", "12", "4" }, steps.Skip(2).Select(s => s.Value));
            Assert.DoesNotContain(steps, s => s.Variable == DHStep.B); // one private key is enough
        }
    }

    [Fact]
    public void Both_Solvers_Recover_The_Phase0_Toy_Exchange() {
        foreach (ISolver solver in BothSolvers) {
            Assert.Equal("4", solver.solve(Toy));
            Assert.Equal(new[] { "4", "18" }, Recovered(solver, Toy).Select(s => s.Value));
        }
    }

    [Theory]
    [InlineData(23, 5)]
    [InlineData(47, 5)]
    [InlineData(59, 2)]
    public void Both_Solvers_Find_Every_Private_Key_In_Phase0_Groups(int p, int g) {
        // g generates every nonzero value mod p in these groups, so each A = g^a has exactly one key in [0, p - 2].
        foreach (ISolver solver in BothSolvers) {
            for (int a = 0; a <= p - 2; a++) {
                BigInteger publicA = BigInteger.ModPow(g, a, p);
                Assert.Equal(a.ToString(), solver.solve($"({p},{g},{publicA},{g})"));
            }
        }
    }

    [Fact]
    public void BruteForce_Reports_The_Number_Of_Tries() {
        var step = Recovered(new DHBruteForceDiscreteLogSolver(), new DIFFIEHELLMAN().instance).First();
        Assert.Contains("after 14 tries", step.HowFound); // x = 0 through 13
    }

    [Fact]
    public void BabyStepGiantStep_Explains_The_Match() {
        var step = Recovered(new DHBabyStepGiantStepSolver(), new DIFFIEHELLMAN().instance).First();
        // m = ceil(sqrt(58)) = 8; 13 = 1 x 8 + 5
        Assert.Contains("Giant step 1 matched baby step 5", step.HowFound);
        Assert.Contains("a = 1 × 8 + 5 = 13", step.HowFound);
        Assert.Contains("(10 multiplications)", step.HowFound); // 8 baby steps, then giant steps 0 and 1
    }

    [Theory]
    [InlineData("(23,2,5,4)")]    // 2 only generates the 11 quadratic residues mod 23, and 5 is not one of them
    public void Both_Solvers_Report_A_Value_That_Is_Not_A_Power_Of_g(string instance) {
        foreach (ISolver solver in BothSolvers) {
            string answer = solver.solve(instance);
            Assert.StartsWith("No solution", answer);
            Assert.Contains("is not a power of g", answer);
        }
    }

    [Fact]
    public void Both_Solvers_Work_In_A_Subgroup() {
        // 2 has order 11 mod 23; 2^7 = 13, and 7 is the smallest key.
        foreach (ISolver solver in BothSolvers)
            Assert.Equal("7", solver.solve("(23,2,13,4)"));
    }

    [Fact]
    public void Composite_Modulus_Is_Reported() {
        // p = 36 and g = 6: the shared secret 6^2 = 0 mod 36 has no inverse, and neither does g.
        string bruteForce = new DHBruteForceDiscreteLogSolver().solve(new DIFFIEHELLMAN("(36,6,1,2,\"HI\")"));
        Assert.StartsWith("No solution", bruteForce);
        Assert.Contains("has no inverse", bruteForce);
        string babyGiant = new DHBabyStepGiantStepSolver().solve(new DIFFIEHELLMAN("(36,6,1,2,\"HI\")"));
        Assert.StartsWith("No solution", babyGiant);
        Assert.Contains("g = 6 has no inverse", babyGiant);
    }

    [Fact]
    public void Solvers_Stop_When_The_Timer_Expires() {
        Assert.Equal(DHBruteForceDiscreteLogSolver.Timeout,
            new DHBruteForceDiscreteLogSolver { timerHasExpired = true }.solve(new DIFFIEHELLMAN()));
        Assert.Equal(DHBabyStepGiantStepSolver.Timeout,
            new DHBabyStepGiantStepSolver { timerHasExpired = true }.solve(new DIFFIEHELLMAN()));
    }

    // --- Verifier ---

    [Theory]
    [InlineData("(13,\"HELLO WORLD\")", true)]
    [InlineData("(13,\"hello world\")", true)]
    [InlineData(" ( 13 , \"HELLO WORLD\" ) ", true)]
    [InlineData("(13,HELLO WORLD)", true)]              // quotes are optional
    [InlineData("(12,\"HELLO WORLD\")", false)]         // wrong key
    [InlineData("(71,\"HELLO WORLD\")", false)]         // 71 = 13 + 58 gives A too, but is not in [0, p - 2]
    [InlineData("(13,\"HELLO WORLE\")", false)]         // right key, wrong message
    [InlineData("(13,\"HELLO\")", false)]               // too short
    public void Verifier_Checks_The_Key_And_The_Message(string certificate, bool expected) {
        Assert.Equal(expected, new DiffieHellmanVerifier().verify(new DIFFIEHELLMAN(), certificate));
    }

    [Theory]
    [InlineData("4", true)]
    [InlineData(" 4 ", true)]
    [InlineData("5", false)]
    [InlineData("26", false)]  // 26 = 4 + 22 gives A too, but is not in [0, p - 2]
    [InlineData("-1", false)]
    public void Verifier_Checks_The_Key_In_Eve_View(string certificate, bool expected) {
        Assert.Equal(expected, new DiffieHellmanVerifier().verify(new DIFFIEHELLMAN(Toy), certificate));
    }

    [Fact]
    public void Verifier_Accepts_The_Advertised_Example_For_The_Default_Instance() {
        Assert.True(new DiffieHellmanVerifier().verify(new DIFFIEHELLMAN(), DiffieHellmanVerifier.CertificateExample));
    }

    [Theory]
    [InlineData(Toy, "four")]
    [InlineData("(59,2,13,23,\"Hello World\")", "13")]                  // a message needs the key and the message
    [InlineData("(59,2,13,23,\"Hello World\")", "(x,\"HELLO WORLD\")")]
    [InlineData("(59,2,13,23,\"Hello World\")", "(13,\"HELL0 WORLD\")")]
    public void Verifier_Rejects_A_Certificate_It_Cannot_Read(string instance, string certificate) {
        Assert.Throws<CertificateParseException>(() => new DiffieHellmanVerifier().verify(new DIFFIEHELLMAN(instance), certificate));
    }

    // NIST ACVP KAS-FFC-SSC vectors (SP 800-56A Rev. 3): group p and g, Alice's private key, both public values and
    // the shared secret z, in hex. Solving at this size is infeasible, but checking a key is one exponentiation.
    [Theory]
    [InlineData("ffdhe2048 tcId 1", "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", "2290E07D2C96137B0E391C8F6609AFC13517F07F0CE606B4B3965E8E06A9632B0D2C56D7BC69A37FD456CAD216DE2B55DFDDF922F1407F624B2AE90C6627CE738DCB7D697CB0867AECB8B5C0901833EC705AB328ECCD3C6C8459F709D51AB57A05F5DE618D41084BA90A2644A63DEB10360F8E90C68DA08402716CBA127B6450FE4623782ED32412EB7A924778515BDCB3A55CB890468F4C74354649715C72B53D8BF8748B0871E00FFA1E46A8A18CCDDB0F27708CC066B4DC7BC1C5EDA5ECCE478A1A53ADEEB589E09B0E2AC5EE7DBAF13BBCF2C0644FA9122CFFE8581B1D8E5F034FCA186FC2A7CAFEB33DEBC236D577F40478F9D7DF46D12B0C870F0791CD", "D15B2174DC6B2D45F0D5EF1DE4D909749501870632F1D41B6A483A57033C37872BD58C47D8405883EA956737EAEFFFA366962A6082C72148A7CA521D9EBCB8F2E61B3CA1720E0B084C2931F061EBF61766471DC82018B1B1873F5EF9F14BA8665AC91EB1FCDF11A44425B3B4177F8AE4717A98E5B9D3F9570857A1D230C40EEF15BD3E96F46830EEB995E6B814DA23205DD6A1408AD4892610D260813A2B4B9EA38CE8F8250C5DB37B2026375EDA1A8CBA439F63D96008F625B56D08275E6E773E9DEE435B9D0A2E831D02CD03AA5D9EBAA7FC752C75B3179FA43D4EE89945DC2C44017C7C9ABCD4A21003B982C4BD398D2C228E4689704518056625517B50AD", "0A528B4BC71FFF42113F2F21BD2BBD17EB2B5F15B0A15EDA4DBB7864429E9655CDA4B256D1655E5CD60062C92097008C6D2A461FC71DA3339DCB9B77D0F30B4FB44CEB48991C0A0AAF5331593BF404469411CE24EACDD12A9AD46A9D3170F1CC28C006BC4D7B18B1948B61C560C04AA1A6F71A726078BDE16D4AB75C164A64F3A8018F204873EBB2F05B4319AB139E9E94B8EA12B7381847FC7AF95E01403998F3001F716CC0C67D50972E8DC21FCCB44AE6BBC09F6776D0555B84765FEB903E52501E3DE577C2532ACF755DC85CBB2A38036FEAA4FDA04F5E38AF55A02B4669273E5406FDFD6D7FC13195FCFCFDE023DD9ACC85F23B0CBE7D4B4CF489CBFD51", "5D52A8867A2B18FC492429E6B78A366E4A9ACFC76CD500B92E993F1EBE29445F394F34E4893A1E39018624A5AF0B27B665C5A8F1957E3043D33F13DDDA808E8024E20DFDCCFCE80C9DE65D5CA18C762828E3A9044E97BFA051007972AB2003C5EC00B7E6D29DEA98E11E0E85405477CBBF9219C018BDA9197657F139E75BA16A6C68BBFA654BC3D45B52EA06E7D65BCB6DCB35E6A05941938D0D195F4FD1C12BDC184C104BF97879A25B69847B973AAD933588EBA91E414A0EE5169259691CB3FE551FE8A748D3F93ED323D01888BCA0C87AEBD0E3BBB48F6836E46D5558F2889EAAB86804C68C1509243C63A24DDEFF0566FF726AD3385ADD44C811CB09B46F")]
    [InlineData("FB tcId 6", "9A8C929EDEC108FFDDAA2CCFCF24962EACDE3C70D8D850B8B1CCFE301B23C819F19BD39CB4A10F1839A76ED3B8A08FDB11658D3198E96275A91D8463885C82C234FC22DA758BAD17C87EA197C9131CFDE9BFFAA41EDDF443A6B4F114B59EF8853705C1037C46E9015F17259F5A80098AC97C7559C7AE82936ED06A8F31DCBDC7D02006A2C8C22D323624855EA3F63FE0EAD6D2FB70E24FE60C5B114CEA1E162293C6FEE8376C0E257B0843A6B5ED4E1ACF365B918E59231F464C7561ECD2E3D78A2364EC3B6973CD2B08E04C37DDEEDE570704EE619121A82095E35770EC65F4F4FCEC6CECCBDFB919ADEBB9B3453FACFB202D7E6034D7EC2002EE19687D7A17", "4EEF7625DB407CBFF5136FD9DABAFEBCEBCB94BCC9F62AB0B56A4384FF0736BFC0C25187DCF1FB946575A7554D499A267621B01986E024DCBB80E10C0EC1975EBDA3B6AEA33C88486BA715F8F33DFADADCA46C483C414A094D34FA35ED8BED37230C93246D4C44382110ECA4FD1A6D8E7F953A72F089AF821DA181E4C1178BA8096E4CC8250D1020CECD82E85E91F544DEE45D0BC5A15E820397821A60D07752D5387A75291E6B94DD4718F4D638CCC3C204F4B08436B4812D46D298511D3EA505B547B3BA3E374BAE7B90F69AAF2E173FC25B2C89331995A37051C71259B11DA729550E5F4E67AAC8B9521403553B137FEF2C012E5F6FF7010F452B768FB837", "6CD08F86779471DA343E06339C95BD867D00FD253F6FDDB5CB6F7D0F", "8EFE5C174A47D1C84E2F670D314E90656721EE96066613F43CB9FD4CCED0529F7DBEFC28926B494F58ADA9EB368B90C4B9863663F797CFFB13273F1F93160AAB68D5A940103051BA7D23555F579F1986F83C4A4AD0FDD545E429DA0F7B7954FA03E6FCA6E2002ECC2CE42BFD75AFAFD65F350E8B0F89978089D22AF90686E40E1C1EB632449354A49C2464E196755578320A8448BDC353ECF879D1CB67E47121CE4809402D5D67973F3A845CA8FAA444C2BDB8B6F3C69D32E3E92D6A5E125049DC7971925D55A3E47E4EFF5CD93FACF08263BD2839D6217DB1451026E7F7B813CB0DA2F752B6B6BEC6FAE5712B0B16C3E3B28C47D3A17D4EA4D65256BDC0AD05", "097A0EF5173351B6DF3F0F25E1E356883CAFDCF5AC100C6FA299F5F017F3BEE62D429960115540F3CB2854AFCC1411B5708F71486A1085C5349FEB698F8B82F777A83B95F4D643B3F3C311EB690AF6CE966C064C71D20092AA00AB6AC7A7B6FB38ECAA786DD4EA02BDE1080388EFDF77A499E10D9CDBD284435C92B9389A48006F48C4D8865343DC5D168515F538EEFFEAC2153919472AD70144CB0AEF2C1E319B15EA31809F44A3479521F9EA2597287C32D2E6DBBD63058BD9DE5597D29115F1D72BDA233C251698B38DB645E12B5B1F4AE65979D7C0F1FA2989B6C6B391387ED59AA1BAB4819B921954DBE25B47CA7DA9D52B3BD0CA6D5B54172845D24391", "38C93767E15011FC41A02638F8611BD6D445F853E3D830FA17C1E74133BB5C7303C1CB4C4C2E6B5F6490742D37F0CA077A6048C6095810A27DC35397B9F5B197962A2C839762B80FE0C49D08756DB48F2D6D3BC09288C0653567AED4226287C31E68177BB2FF37963D43CB91B47A6CE6631FB65EF0ADE91E51D725B7DBD3DC6A7DB051ADBF2C8CE7240B293867BA767EBF261B9602318CDA369F4AEFA19C901C083FC9BD1CEE6BBA7985BE8A37D0F6A8BAB1AE1EA31AE9F8FBA83524C3064A23C437DEBCA464189773634D193CE1D92E2079783AFC0A2C39763EABF5B76001A9694DDB3B6A5A39DD0271439029FD80AB612A95AAEFBFC23BE84E1A1FB2D76F50")]
    public void Verifier_And_Shared_Secret_Match_NIST_Vectors(string group, string pHex, string gHex, string privateHex,
        string publicAHex, string publicBHex, string sharedHex) {
        BigInteger p = FromHex(pHex), g = FromHex(gHex), privateA = FromHex(privateHex);
        var problem = new DIFFIEHELLMAN($"({p},{g},{FromHex(publicAHex)},{FromHex(publicBHex)})");

        Assert.True(new DiffieHellmanVerifier().verify(problem, privateA.ToString()), group);
        Assert.False(new DiffieHellmanVerifier().verify(problem, (privateA + 1).ToString()), group);

        var steps = new List<DHStep>();
        Assert.Equal(privateA.ToString(), DHKeyRecovery.FinishFromPrivateKey(problem, privateA, steps));
        Assert.Equal(FromHex(sharedHex).ToString(), steps.Single(s => s.Variable == DHStep.S).Value);
    }

    private static BigInteger FromHex(string hex) =>
        BigInteger.Parse("0" + hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    // --- Visualization ---

    private static List<API_TableJSON> Frames(DIFFIEHELLMAN problem, ISolver solver) =>
        new DHKnowledgeTableVisualization()
            .StepsVisualization(problem, solver.GetSteps(problem.instance))
            .Cast<API_TableJSON>().ToList();

    private static TableRow Row(API_TableJSON table, string id) => table.rows.Single(r => r.id == id);

    [Fact]
    public void Visualization_Starts_With_Only_The_Public_Values_Known() {
        var message = new DHKnowledgeTableVisualization().visualize(new DIFFIEHELLMAN());
        Assert.Equal(new[] { "p", "g", "A", "B", "c", "a", "b", "s", "m" }, message.rows.Select(r => r.id));
        Assert.Equal("25, 23, 8, 8, 10, 18, 35, 10, 12, 8, 42", Row(message, "c").cells["value"]);
        Assert.All(DHStep.Secrets, secret => Assert.Equal("?", Row(message, secret).cells["value"]));

        var eveView = new DHKnowledgeTableVisualization().visualize(new DIFFIEHELLMAN(Toy));
        Assert.Equal(new[] { "p", "g", "A", "B", "a", "b", "s" }, eveView.rows.Select(r => r.id));
    }

    [Fact]
    public void Visualization_Fills_In_a_Then_s_Then_The_Message_While_b_Stays_Unknown() {
        var frames = Frames(new DIFFIEHELLMAN(), new DHBruteForceDiscreteLogSolver());
        Assert.Equal(2 + 11, frames.Count);

        var first = frames[0];
        Assert.Equal("13", Row(first, "a").cells["value"]);
        Assert.Equal("ElementHighlight", Row(first, "a").color);
        Assert.Equal("?", Row(first, "s").cells["value"]);

        var afterThirdLetter = frames[2 + 2];
        Assert.Equal("8, 5, 12, ?, ?, ?, ?, ?, ?, ?, ? = \"HEL????????\"", Row(afterThirdLetter, "m").cells["value"]);
        Assert.Equal("Step 5 of 13: found letter 3 of 11", afterThirdLetter.title);

        var last = frames[^1];
        Assert.Equal("40", Row(last, "s").cells["value"]);
        Assert.Equal("?", Row(last, "b").cells["value"]);
        Assert.StartsWith("Never needed", Row(last, "b").cells["howFound"]);
        Assert.Contains("= \"HELLO WORLD\"", Row(last, "m").cells["value"]);
        Assert.Equal("Solution", Row(last, "m").color);
    }

    [Fact]
    public void Visualization_Marks_The_Shared_Secret_As_The_Result_In_Eve_View() {
        var frames = Frames(new DIFFIEHELLMAN(Toy), new DHBabyStepGiantStepSolver());
        Assert.Equal(2, frames.Count);
        Assert.Equal("18", Row(frames[^1], "s").cells["value"]);
        Assert.Equal("Solution", Row(frames[^1], "s").color);
    }
}
