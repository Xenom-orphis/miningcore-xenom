using Miningcore.Blockchain.Kaspa.Custom.Xenom;

namespace Miningcore.Crypto.Hashing.XenomHash;

public class XenomHasher: IHashAlgorithm
{
    private readonly XenomMatrix _xenomMatrix;

    public XenomHasher(XenomMatrix xenomMatrix)
    {
        _xenomMatrix = xenomMatrix;
    }

    public void Digest(ReadOnlySpan<byte> data, Span<byte> result, params Object[] extra)
    {
        // Perform heavy hashing using XenomMatrix
        var heavyHash = _xenomMatrix.HeavyHash(data.ToArray());

        // Copy the heavy hash result to the output span
        heavyHash.AsSpan().CopyTo(result);
    }

    public byte[] ComputeHash(byte[] data)
    {
        // Perform heavy hashing and return the result
        return _xenomMatrix.HeavyHash(data);
    }
}
