using System;
using System.Globalization;
using System.Numerics;
using System.Collections.Concurrent;
using System.Text;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
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

    public ulong Uint64()
    {
        ulong result = RotateLeft64(this.s[0] + this.s[3], 23) + this.s[0];
        ulong t = this.s[1] << 17;
        this.s[2] ^= this.s[0];
        this.s[3] ^= this.s[1];
        this.s[1] ^= this.s[2];
        this.s[0] ^= this.s[3];
        this.s[2] ^= t;
        this.s[3] = RotateLeft64(this.s[3], 45);
        return result;
    }

    private static ulong RotateLeft64(ulong value, int offset)
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

    private ushort[,] GenerateMatrix(ReadOnlySpan<byte> prePowHash)
    {
        ushort[,] matrix = new ushort[64, 64];

        var generator = new KaspaXoShiRo256PlusPlus(prePowHash.ToArray());

        while (true)
        {
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < 64; j += 16)
                {
                    ulong val = generator.Uint64();
                    for (int shift = 0; shift < 16; shift++)
                    {
                        matrix[i, j + shift] = (ushort)((val >> (4 * shift)) & 0x0F);
                    }
                }
            }
            if (ComputeRank(matrix) == 64)
                return matrix;
        }
    }

    protected virtual int ComputeRank(ushort[,] matrix)
    {
        int numRows = matrix.GetLength(0); // Should be 64
        int numCols = matrix.GetLength(1); // Should be 64
        int rank = 0;

        // Create a copy of the matrix to avoid modifying the original
        ushort[,] mat = new ushort[numRows, numCols];
        Array.Copy(matrix, mat, matrix.Length);

        // Perform Gaussian elimination over GF(2)
        for (int col = 0; col < numCols; col++)
        {
            int pivotRow = -1;
            for (int row = rank; row < numRows; row++)
            {
                if ((mat[row, col] & 1) != 0) // Check if the least significant bit is 1
                {
                    pivotRow = row;
                    break;
                }
            }

            if (pivotRow == -1)
            {
                continue; // No pivot in this column
            }

            // Swap the current row with the pivot row
            if (pivotRow != rank)
            {
                // Swap rows rank and pivotRow
                for (int k = 0; k < numCols; k++)
                {
                    ushort temp = mat[rank, k];
                    mat[rank, k] = mat[pivotRow, k];
                    mat[pivotRow, k] = temp;
                }
            }

            // Eliminate the current column entries in other rows
            for (int row = 0; row < numRows; row++)
            {
                if (row != rank && (mat[row, col] & 1) != 0)
                {
                    for (int k = col; k < numCols; k++)
                    {
                        mat[row, k] ^= mat[rank, k];
                    }
                }
            }

            rank++;
        }

        return rank;
    }

    protected virtual Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {
        // Initialize the vector to hold 64 bytes
        byte[] vec = new byte[64];
        for (int i = 0; i < 32; i++)
        {
            byte element = data[i];
            vec[2 * i] = (byte)(element >> 4);       // High 4 bits
            vec[2 * i + 1] = (byte)(element & 0x0F); // Low 4 bits
        }

        // Assuming 'matrix' is a field similar to 'self.0' in Rust
        ushort[,] matrix = GenerateMatrix(prePowHash);

        // Perform matrix-vector multiplication and process sums
        byte[] product = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            ushort sum1 = 0;
            ushort sum2 = 0;
            for (int j = 0; j < 64; j++)
            {
                sum1 += (ushort)(matrix[2 * i, j] * vec[j]);
                sum2 += (ushort)(matrix[2 * i + 1, j] * vec[j]);
            }

            // Process the sums as per Rust code
            byte processedSum1 = (byte)(((sum1 & 0xF) ^ ((sum1 >> 4) & 0xF) ^ ((sum1 >> 8) & 0xF)) << 4);
            byte processedSum2 = (byte)((sum2 & 0xF) ^ ((sum2 >> 4) & 0xF) ^ ((sum2 >> 8) & 0xF));

            product[i] = (byte)(processedSum1 | processedSum2);
        }

        // XOR the product with the original hash bytes
        for (int i = 0; i < 32; i++)
        {
            product[i] ^= data[i];
        }



        return (Span<byte>) product;
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

            blockHeaderHasher.Digest(stream.ToArray(), hashBytes);

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
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
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
