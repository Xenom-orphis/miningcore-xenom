using System;
using System.Globalization;
using System.Numerics;
using System.Collections.Concurrent;
using System.Text;
using Miningcore.Blockchain.Kaspa.Custom.Xenom;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Crypto.Hashing.XenomHash;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NLog;
using kaspad = Miningcore.Blockchain.Kaspa.Kaspad;

namespace Miningcore.Blockchain.Kaspa;

public class KaspaXoShiRo256PlusPlus
{
    private ulong[] s = new ulong[4];

    public KaspaXoShiRo256PlusPlus(Span<byte> prePowHash)
    {
        Contract.Requires<ArgumentException>(prePowHash.Length >= 32);

        for (int i = 0; i < 4; i++)
        {
            s[i] = BitConverter.ToUInt64(prePowHash.Slice(i * 8, 8));
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

    private static ulong RotateRight64(ulong value, int offset)
    {
        return (value >> offset) | (value << (64 - offset));
    }
}

public class KaspaJob
{
    private static readonly ILogger logger = LogManager.GetCurrentClassLogger();
    protected IMasterClock clock;
    protected double shareMultiplier;
    public kaspad.RpcBlock BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }
    public string JobId { get; protected set; }
    public uint256 blockTargetValue { get; protected set; }

    protected object[] jobParams;
    private readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);

    protected IHashAlgorithm blockHeaderHasher;
    protected IHashAlgorithm coinbaseHasher;
    protected IHashAlgorithm shareHasher;

    public KaspaJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
    {
        Contract.RequiresNonNull(customBlockHeaderHasher);
        Contract.RequiresNonNull(customCoinbaseHasher);
        Contract.RequiresNonNull(customShareHasher);

        this.blockHeaderHasher = customBlockHeaderHasher;
        this.coinbaseHasher = customCoinbaseHasher;
        this.shareHasher = customShareHasher;
    }

    protected bool RegisterSubmit(string nonce)
    {
        var key = new StringBuilder()
            .Append(nonce)
            .ToString();

        return submissions.TryAdd(key, true);
    }

    protected virtual ushort[][] GenerateMatrix(Span<byte> prePowHash)
    {


        if(prePowHash.Length != 32)
            throw new ArgumentException("hashBytes must be exactly 32 bytes");

        var generator = new XoShiRo256PlusPlus(prePowHash.ToArray());
        var matrix = new ushort[64][];

        for(int i = 0; i < 64; i++)
        {
            matrix[i] = new ushort[64];
        }

        // Matrix generation logic
        while(true)
        {
            for(int i = 0; i < 64; i++)
            {
                for(int j = 0; j < 64; j += 16)
                {
                    ulong value = generator.Next();
                    for(int shift = 0; shift < 16; shift++)
                    {
                        matrix[i][j + shift] = (ushort) ((value >> (4 * shift)) & 0x0F);
                    }
                }
            }

            if(ComputeRank(matrix) == 64)
                break;

        }
        return new XenomMatrix(matrix)._matrix;
    }

    private static int ComputeRank(ushort[][] matrix)
    {
        int rank = 0;
        double epsilon = 1e-9;
        var rows = Enumerable.Range(0, 64).Select(i => Enumerable.Range(0, 64).Select(j => (double)matrix[i][j]).ToArray()).ToArray();
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



    protected virtual Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {
        var xenomMatrix = XenomMatrix.Generate(prePowHash.ToArray());
        var hash = xenomMatrix.HeavyHash(data.ToArray());
        return hash;
    }

    protected virtual Span<byte> SerializeCoinbase(Span<byte> prePowHash, long timestamp, ulong nonce)
    {
        Span<byte> hashBytes = stackalloc byte[32];

        using(var stream = new MemoryStream())
        {
            stream.Write(prePowHash);
            stream.Write(BitConverter.GetBytes((ulong) timestamp));
            stream.Write(new byte[32]); // 32 zero bytes padding
            stream.Write(BitConverter.GetBytes(nonce));

            coinbaseHasher.Digest(stream.ToArray(), hashBytes);

            return (Span<byte>) hashBytes.ToArray();
        }
    }

    protected virtual Span<byte> SerializeHeader(kaspad.RpcBlockHeader header, bool isPrePow = true)
    {
        ulong nonce = isPrePow ? 0 : header.Nonce;
        long timestamp = isPrePow ? 0 : header.Timestamp;
        Span<byte> hashBytes = stackalloc byte[32];
        //var blockHashBytes = Encoding.UTF8.GetBytes(KaspaConstants.CoinbaseBlockHash);

        using(var stream = new MemoryStream())
        {
            var versionBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ushort) header.Version).ReverseInPlace() : BitConverter.GetBytes((ushort) header.Version);
            stream.Write(versionBytes);
            var parentsBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) header.Parents.Count).ReverseInPlace() : BitConverter.GetBytes((ulong) header.Parents.Count);
            stream.Write(parentsBytes);

            foreach (var parent in header.Parents)
            {
                var parentHashesBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) parent.ParentHashes.Count).ReverseInPlace() : BitConverter.GetBytes((ulong) parent.ParentHashes.Count);
                stream.Write(parentHashesBytes);

                foreach (var parentHash in parent.ParentHashes)
                {
                    stream.Write(parentHash.HexToByteArray());
                }
            }

            stream.Write(header.HashMerkleRoot.HexToByteArray());
            stream.Write(header.AcceptedIdMerkleRoot.HexToByteArray());
            stream.Write(header.UtxoCommitment.HexToByteArray());

            var timestampBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) timestamp).ReverseInPlace() : BitConverter.GetBytes((ulong) timestamp);
            stream.Write(timestampBytes);
            var bitsBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.Bits).ReverseInPlace() : BitConverter.GetBytes(header.Bits);
            stream.Write(bitsBytes);
            var nonceBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(nonce).ReverseInPlace() : BitConverter.GetBytes(nonce);
            stream.Write(nonceBytes);
            var daaScoreBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.DaaScore).ReverseInPlace() : BitConverter.GetBytes(header.DaaScore);
            stream.Write(daaScoreBytes);
            var blueScoreBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes(header.BlueScore).ReverseInPlace() : BitConverter.GetBytes(header.BlueScore);
            stream.Write(blueScoreBytes);

            var blueWork = header.BlueWork.PadLeft(header.BlueWork.Length + (header.BlueWork.Length % 2), '0');
            var blueWorkBytes = blueWork.HexToByteArray();

            var blueWorkLengthBytes = (!BitConverter.IsLittleEndian) ? BitConverter.GetBytes((ulong) blueWorkBytes.Length).ReverseInPlace() : BitConverter.GetBytes((ulong) blueWorkBytes.Length);
            stream.Write(blueWorkLengthBytes);
            stream.Write(blueWorkBytes);

            stream.Write(header.PruningPoint.HexToByteArray());
            var xenomMatrix = XenomMatrix.Generate(hashBytes.ToArray());
            new XenomHasher(xenomMatrix).Digest(stream.ToArray(), hashBytes);

            return (Span<byte>) hashBytes.ToArray();
        }
    }

    protected virtual (string, ulong[]) SerializeJobParamsData(Span<byte> prePowHash)
    {
        ulong[] preHashU64s = new ulong[4];
        string preHashStrings = "";

        for (int i = 0; i < 4; i++)
        {
            var slice = prePowHash.Slice(i * 8, 8);

            preHashStrings += slice.ToHexString().PadLeft(16, '0');
            preHashU64s[i] = BitConverter.ToUInt64(slice);
        }

        return (preHashStrings, preHashU64s);
    }

    protected virtual Share ProcessShareInternal(StratumConnection worker, string nonce)
    {
        var context = worker.ContextAs<KaspaWorkerContext>();

        BlockTemplate.Header.Nonce = Convert.ToUInt64(nonce, 16);

        var prePowHashBytes = SerializeHeader(BlockTemplate.Header, true);
        var coinbaseBytes = SerializeCoinbase(prePowHashBytes, BlockTemplate.Header.Timestamp, BlockTemplate.Header.Nonce);

        Span<byte> hashCoinbaseBytes = stackalloc byte[32];
        shareHasher.Digest(ComputeCoinbase(prePowHashBytes, coinbaseBytes), hashCoinbaseBytes);

        var targetHashCoinbaseBytes = new Target(new BigInteger(hashCoinbaseBytes.ToNewReverseArray(), true, true));
        var hashCoinbaseBytesValue = targetHashCoinbaseBytes.ToUInt256();
        //throw new StratumException(StratumError.LowDifficultyShare, $"nonce: {nonce} ||| hashCoinbaseBytes: {hashCoinbaseBytes.ToHexString()} ||| BigInteger: {targetHashCoinbaseBytes.ToBigInteger()} ||| Target: {hashCoinbaseBytesValue} - [stratum: {KaspaUtils.DifficultyToTarget(context.Difficulty)} - blockTemplate: {blockTargetValue}] ||| BigToCompact: {KaspaUtils.BigToCompact(targetHashCoinbaseBytes.ToBigInteger())} - [stratum: {KaspaUtils.BigToCompact(KaspaUtils.DifficultyToTarget(context.Difficulty))} - blockTemplate: {BlockTemplate.Header.Bits}] ||| shareDiff: {(double) new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier} - [stratum: {context.Difficulty} - blockTemplate: {KaspaUtils.TargetToDifficulty(KaspaUtils.CompactToBig(BlockTemplate.Header.Bits)) * (double) KaspaConstants.MinHash}]");

        // calc share-diff
        var shareDiff = (double) new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier;

        // diff check
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = hashCoinbaseBytesValue <= blockTargetValue;
        //var isBlockCandidate = true;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;
                logger.Info("RATIO ${}", ratio);
                if(ratio < 0.99)


                    //throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }


        }

        var result = new Share
        {
            BlockHeight = (long) BlockTemplate.Header.DaaScore,
            NetworkDifficulty = Difficulty,
            Difficulty = context.Difficulty / shareMultiplier
        };

        if(isBlockCandidate)
        {
            var hashBytes = SerializeHeader(BlockTemplate.Header, false);

            result.IsBlockCandidate = true;
            result.BlockHash = hashBytes.ToHexString();
        }

        return result;
    }

    public object[] GetJobParams()
    {
        return jobParams;
    }

    public virtual Share ProcessShare(StratumConnection worker, string nonce)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<KaspaWorkerContext>();

        // We don't need "0x"
        nonce = (nonce.StartsWith("0x")) ? nonce.Substring(2) : nonce;

        // Add extranonce to nonce if enabled and submitted nonce is shorter than expected (16 - <extranonce length> characters)
        if (nonce.Length <= (KaspaConstants.NonceLength - context.ExtraNonce1.Length))
        {
            nonce = context.ExtraNonce1.PadRight(KaspaConstants.NonceLength - context.ExtraNonce1.Length, '0') + nonce;
        }

        // dupe check
        if(!RegisterSubmit(nonce))
            throw new StratumException(StratumError.DuplicateShare, $"duplicate share");

        return ProcessShareInternal(worker, nonce);
    }

    public virtual void Init(kaspad.RpcBlock blockTemplate, string jobId, double shareMultiplier)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));
        Contract.RequiresNonNull(shareMultiplier);

        JobId = jobId;
        this.shareMultiplier = shareMultiplier;

        var target = new Target(KaspaUtils.CompactToBig(blockTemplate.Header.Bits));
        Difficulty = KaspaUtils.TargetToDifficulty(target.ToBigInteger()) * (double) KaspaConstants.MinHash;
        blockTargetValue = target.ToUInt256();
        BlockTemplate = blockTemplate;

        var (largeJob, regularJob) = SerializeJobParamsData(SerializeHeader(blockTemplate.Header));
        jobParams = new object[]
        {
            JobId,
            largeJob + BitConverter.GetBytes(blockTemplate.Header.Timestamp).ToHexString().PadLeft(16, '0'),
            regularJob,
            blockTemplate.Header.Timestamp,
        };
    }
}
