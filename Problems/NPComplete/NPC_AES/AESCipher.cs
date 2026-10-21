namespace API.Problems.NPComplete.NPC_AES;

/// <summary>
/// One AES state recorded while encrypting: which operation just ran, in which round, the 16 state bytes after
/// it, and the round key for an AddRoundKey.
/// </summary>
record AESRoundState(string Operation, int Round, byte[] State, byte[]? RoundKey = null);

/// <summary>
/// AES-128 on a single 16-byte block, as specified in FIPS 197: key expansion into 11 round keys, then an initial
/// AddRoundKey and 10 rounds of SubBytes, ShiftRows, MixColumns (not in the last round) and AddRoundKey.
///
/// The state is kept as 16 bytes in input order, which FIPS 197 reads column by column: byte r + 4c is row r of
/// column c. Written for clarity first; the only speed-ups are plain loops and looked-up products, since the key search
/// runs it up to 2^24 times.
/// </summary>
static class AESCipher {

    public const int BlockSize = 16;
    public const int KeySize = 16;
    public const int Rounds = 10;

    public const string Input = "Input";
    public const string AddRoundKeyStep = "AddRoundKey";
    public const string SubBytesStep = "SubBytes";
    public const string ShiftRowsStep = "ShiftRows";
    public const string MixColumnsStep = "MixColumns";

    /// <summary>The S-box, built from its definition: the inverse in GF(2^8), then an affine transformation.</summary>
    public static readonly byte[] SBox = BuildSBox();
    private static readonly byte[] InverseSBox = Invert(SBox);

    // MixColumns multiplies by small constants only, so each product is looked up rather than computed: the key
    // search runs these millions of times.
    // Times[f][b] = f x b, for each factor f the two matrices use.
    private static readonly byte[][] Times = BuildMultiplicationTables(1, 2, 3, 9, 11, 13, 14);

    // Round constants for AES-128's 10 rounds: successive powers of 2 in GF(2^8).
    private static readonly byte[] Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    // --- Encryption and decryption ---

    public static byte[] Encrypt(byte[] block, byte[] key) => Encrypt(block, ExpandKey(key), trace: null);

    /// <summary>Encrypts one block, recording the state after every operation: the input plus 40 operations.</summary>
    public static List<AESRoundState> EncryptWithTrace(byte[] block, byte[] key) {
        var trace = new List<AESRoundState>();
        Encrypt(block, ExpandKey(key), trace);
        return trace;
    }

    public static byte[] Decrypt(byte[] block, byte[] key) {
        CheckLength(block, BlockSize, "block");
        byte[][] roundKeys = ExpandKey(key);
        byte[] state = AddRoundKey(block, roundKeys[Rounds]);
        for (int round = Rounds - 1; round >= 0; round--) {
            state = InverseSubBytes(InverseShiftRows(state));
            state = AddRoundKey(state, roundKeys[round]);
            if (round > 0)
                state = InverseMixColumns(state);
        }
        return state;
    }

    private static byte[] Encrypt(byte[] block, byte[][] roundKeys, List<AESRoundState>? trace) {
        CheckLength(block, BlockSize, "block");
        trace?.Add(new AESRoundState(Input, 0, (byte[])block.Clone()));

        byte[] state = AddRoundKey(block, roundKeys[0]);
        trace?.Add(new AESRoundState(AddRoundKeyStep, 0, state, roundKeys[0]));
        for (int round = 1; round <= Rounds; round++) {
            state = SubBytes(state);
            trace?.Add(new AESRoundState(SubBytesStep, round, state));
            state = ShiftRows(state);
            trace?.Add(new AESRoundState(ShiftRowsStep, round, state));
            if (round < Rounds) {
                state = MixColumns(state);
                trace?.Add(new AESRoundState(MixColumnsStep, round, state));
            }
            state = AddRoundKey(state, roundKeys[round]);
            trace?.Add(new AESRoundState(AddRoundKeyStep, round, state, roundKeys[round]));
        }
        return state;
    }

    // --- Key expansion ---

    /// <summary>
    /// Expands a 16-byte key into 11 round keys of 16 bytes. Word i (4 bytes) is word i - 4 XOR word i - 1, and
    /// every fourth word first has word i - 1 rotated, passed through the S-box and XORed with a round constant.
    /// </summary>
    public static byte[][] ExpandKey(byte[] key) {
        CheckLength(key, KeySize, "key");
        // All 44 words in one array: word i is bytes 4i to 4i + 3, and round key r is words 4r to 4r + 3.
        var words = new byte[BlockSize * (Rounds + 1)];
        key.CopyTo(words, 0);
        var temp = new byte[4];
        for (int i = 4; i < 4 * (Rounds + 1); i++) {
            Array.Copy(words, 4 * (i - 1), temp, 0, 4);
            if (i % 4 == 0) {
                (temp[0], temp[1], temp[2], temp[3]) = (SBox[temp[1]], SBox[temp[2]], SBox[temp[3]], SBox[temp[0]]); // RotWord, SubWord
                temp[0] ^= Rcon[i / 4 - 1];
            }
            for (int j = 0; j < 4; j++)
                words[4 * i + j] = (byte)(words[4 * (i - 4) + j] ^ temp[j]);
        }
        var roundKeys = new byte[Rounds + 1][];
        for (int r = 0; r <= Rounds; r++)
            roundKeys[r] = words[(BlockSize * r)..(BlockSize * (r + 1))];
        return roundKeys;
    }

    // --- Round functions ---

    public static byte[] SubBytes(byte[] state) => Substitute(state, SBox);

    private static byte[] InverseSubBytes(byte[] state) => Substitute(state, InverseSBox);

    private static byte[] Substitute(byte[] state, byte[] box) {
        var result = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
            result[i] = box[state[i]];
        return result;
    }

    /// <summary>Row r moves r places to the left: new [r, c] = old [r, (c + r) mod 4].</summary>
    public static byte[] ShiftRows(byte[] state) {
        var result = new byte[BlockSize];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                result[r + 4 * c] = state[r + 4 * ((c + r) % 4)];
        return result;
    }

    private static byte[] InverseShiftRows(byte[] state) {
        var result = new byte[BlockSize];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                result[r + 4 * ((c + r) % 4)] = state[r + 4 * c];
        return result;
    }

    /// <summary>Each column is multiplied in GF(2^8) by the fixed matrix with rows (2 3 1 1), (1 2 3 1), ...</summary>
    public static byte[] MixColumns(byte[] state) => MixEachColumn(state, 2, 3, 1, 1);

    /// <summary>The inverse matrix has rows (14 11 13 9), (9 14 11 13), ...</summary>
    private static byte[] InverseMixColumns(byte[] state) => MixEachColumn(state, 14, 11, 13, 9);

    private static byte[] MixEachColumn(byte[] state, byte m0, byte m1, byte m2, byte m3) {
        var result = new byte[BlockSize];
        byte[] row = { m0, m1, m2, m3 };
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                byte sum = 0;
                // Row r of the matrix is the first row rotated right r places.
                for (int i = 0; i < 4; i++)
                    sum ^= Times[row[(i - r + 4) % 4]][state[i + 4 * c]];
                result[r + 4 * c] = sum;
            }
        }
        return result;
    }

    public static byte[] AddRoundKey(byte[] state, byte[] roundKey) {
        var result = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
            result[i] = (byte)(state[i] ^ roundKey[i]);
        return result;
    }

    // --- GF(2^8) arithmetic, modulo x^8 + x^4 + x^3 + x + 1 ---

    /// <summary>Multiplies two bytes as polynomials over GF(2), reducing by the AES polynomial (0x11b).</summary>
    public static byte Multiply(byte a, byte b) {
        int product = 0, x = a;
        for (int y = b; y != 0; y >>= 1) {
            if ((y & 1) != 0)
                product ^= x;
            x <<= 1;
            if ((x & 0x100) != 0)
                x ^= 0x11b;
        }
        return (byte)product;
    }

    private static byte[] BuildSBox() {
        var sbox = new byte[256];
        for (int value = 0; value < 256; value++) {
            // The multiplicative inverse is value^254 (every nonzero value has value^255 = 1); 0 maps to 0.
            byte inverse = 1;
            for (int i = 0; i < 254; i++)
                inverse = Multiply(inverse, (byte)value);
            if (value == 0)
                inverse = 0;
            // Affine transformation: b XOR its rotations left by 1, 2, 3 and 4 bits, XOR 0x63.
            int b = inverse, result = 0x63;
            for (int shift = 0; shift <= 4; shift++)
                result ^= ((b << shift) | (b >> (8 - shift))) & 0xff;
            sbox[value] = (byte)result;
        }
        return sbox;
    }

    private static byte[][] BuildMultiplicationTables(params byte[] factors) {
        var tables = new byte[factors.Max() + 1][];
        foreach (byte factor in factors) {
            tables[factor] = new byte[256];
            for (int b = 0; b < 256; b++)
                tables[factor][b] = Multiply(factor, (byte)b);
        }
        return tables;
    }

    private static byte[] Invert(byte[] sbox) {
        var inverse = new byte[256];
        for (int i = 0; i < 256; i++)
            inverse[sbox[i]] = (byte)i;
        return inverse;
    }

    private static void CheckLength(byte[] bytes, int length, string name) {
        if (bytes.Length != length)
            throw new ArgumentException($"AES-128 needs a {length}-byte {name}, got {bytes.Length} bytes", name);
    }
}
