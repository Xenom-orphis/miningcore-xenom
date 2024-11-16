using System.Collections.Concurrent;
using System.Security.Cryptography;
using Miningcore.Blockchain.Kaspa.Kaspad;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.XenomHash;
using Miningcore.Time;
using NBitcoin;


namespace Miningcore.Blockchain.Kaspa.Custom.Xenom;


public class XoShiRo256PlusPlus
{
    private ulong[] s = new ulong[4];

    public XoShiRo256PlusPlus(byte[] hash)
    {
        if (hash.Length < 32)
            throw new ArgumentException("Hash must be at least 32 bytes long.");

        // Split the hash into four 64-bit values
        for (int i = 0; i < 4; i++)
        {
            s[i] = BitConverter.ToUInt64(hash, i * 8);
        }
    }

    public ulong Next()
    {
        // Calculate the result of the next number
        ulong result = RotateLeft(s[0] + s[3], 23) + s[0];

        // Perform the XoShiRo256++ state transitions
        ulong t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;
        s[3] = RotateLeft(s[3], 45);

        return result;
    }

    private static ulong RotateLeft(ulong value, int offset)
    {
        return (value << offset) | (value >> (64 - offset));
    }
}
public class XenomMatrix
{
    private readonly ushort[,] _matrix;

    public XenomMatrix(ushort[,] matrix)
    {
        _matrix = matrix;
    }

    public static XenomMatrix Generate(byte[] prePowHash)
    {
        var generator = new XoShiRo256PlusPlus(prePowHash);
        var matrix = new ushort[64, 64];

        while (true)
        {
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < 64; j += 16)
                {
                    ulong value = generator.Next();
                    for (int shift = 0; shift < 16; shift++)
                    {
                        matrix[i, j + shift] = (ushort)((value >> (4 * shift)) & 0x0F);
                    }
                }
            }

            if (ComputeRank(matrix) == 64)
                break;
        }

        return new XenomMatrix(matrix);
    }

    public byte[] HeavyHash(byte[] hash)
    {
        var result = new byte[hash.Length];
        for (int i = 0; i < hash.Length; i++)
        {
            // Ensure the row index is within bounds
            int row = hash[i] % 64;
            for (int j = 0; j < 64; j++)
            {
                result[i] ^= (byte)(_matrix[row, j] & 0xFF);
            }
        }

        return result;
    }

    private static int ComputeRank(ushort[,] matrix)
    {
        int rank = 0;
        double epsilon = 1e-9;
        var rows = Enumerable.Range(0, 64).Select(i => Enumerable.Range(0, 64).Select(j => (double)matrix[i, j]).ToArray()).ToArray();
        bool[] selected = new bool[64];

        for (int i = 0; i < 64; i++)
        {
            int pivotRow = -1;
            for (int j = 0; j < 64; j++)
            {
                if (!selected[j] && Math.Abs(rows[j][i]) > epsilon)
                {
                    pivotRow = j;
                    break;
                }
            }

            if (pivotRow == -1) continue;

            selected[pivotRow] = true;
            double pivotValue = rows[pivotRow][i];
            for (int k = i; k < 64; k++)
            {
                rows[pivotRow][k] /= pivotValue;
            }

            for (int j = 0; j < 64; j++)
            {
                if (j != pivotRow && Math.Abs(rows[j][i]) > epsilon)
                {
                    for (int k = i; k < 64; k++)
                    {
                        rows[j][k] -= rows[pivotRow][k] * rows[j][i];
                    }
                }
            }

            rank++;
        }

        return rank;
    }
}




public class XenomJob  : KaspaJob
{

    protected IMasterClock clock;
    protected double shareMultiplier;
    public RpcBlock BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }
    public string JobId { get; protected set; }
    public uint256 blockTargetValue { get; protected set; }

    protected object[] jobParams;
    private readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    public XenomJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher) : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {
    }
    public override void Init(RpcBlock blockTemplate, string jobId, double shareMultiplier)
    {
        base.Init(blockTemplate, jobId, shareMultiplier);

        var prePowHash = SerializeHeader(blockTemplate.Header, true);
        var xenomMatrix = XenomMatrix.Generate(prePowHash.ToArray());

        // Replace hashing logic with Xenom's heavy hashing
        blockHeaderHasher = new XenomHasher(xenomMatrix);
    }

    protected override Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {
        var xenomMatrix = XenomMatrix.Generate(prePowHash.ToArray());
        var hash = xenomMatrix.HeavyHash(data.ToArray());
        return hash;
    }
}
