#if NETCOREAPP3_0_OR_GREATER
namespace Konscious.Security.Cryptography;

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

internal static class Argon2CoreIntrinsics
{
    public static void XorLanes(Argon2Lane[] lanes)
    {
        var data = lanes[0][lanes[0].BlockCount - 1].Span;

        foreach (var lane in lanes.Skip(1))
        {
            var block = lane[lane.BlockCount - 1].Span;

            for (var b = 0; b < 128; ++b)
            {
                if (!BitConverter.IsLittleEndian)
                {
                    block[b] = (block[b] >> 56) ^
                        ((block[b] >> 40) & 0xff00UL) ^
                        ((block[b] >> 24) & 0xff0000UL) ^
                        ((block[b] >> 8) & 0xff000000UL) ^
                        ((block[b] << 8) & 0xff00000000UL) ^
                        ((block[b] << 24) & 0xff0000000000UL) ^
                        ((block[b] << 40) & 0xff000000000000UL) ^
                        ((block[b] << 56) & 0xff00000000000000UL);
                }

                data[b] ^= block[b];
            }
        }
    }

    public static byte[] Finalize(Argon2Lane[] lanes, int tagLine)
    {
        XorLanes(lanes);

        var ds = new LittleEndianActiveStream();
        ds.Expose(lanes[0][lanes[0].BlockCount - 1]);

        ModifiedBlake2.Blake2Prime(lanes[0][1], ds, tagLine);
        var result = new byte[tagLine];
        var tmp = MemoryMarshal.Cast<ulong, byte>(lanes[0][1].Span).Slice(0, result.Length);
        tmp.CopyTo(result);
        return result;
    }

    public static unsafe void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refb, ReadOnlySpan<ulong> prev)
    {
        if (Avx2.IsSupported)
        {
            fixed (ulong* state = new ulong[dest.Length])
            {

                var stateVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(new Span<ulong>(state, dest.Length));
                var refbVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(refb);
                var prevVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(prev);
                var destVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(dest);

                for (var n = 0; n < stateVectors.Length; ++n)
                {
                    stateVectors[n] = Avx2.Xor(refbVectors[n], prevVectors[n]);
                    destVectors[n] = Avx2.Xor(stateVectors[n], destVectors[n]);
                }

                for (var i = 0; i < 8; ++i)
                {

                    ModifiedBlake2Intrinsics.DoRoundColumns(state, i);
                }

                for (var i = 0; i < 8; ++i)
                    ModifiedBlake2Intrinsics.DoRoundRows(state, i);

                for (var n = 0; n < 128; ++n)
                    dest[n] ^= state[n];
            }
        }
    }
}

#endif
