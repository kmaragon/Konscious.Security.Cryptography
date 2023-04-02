#if NET6_0_OR_GREATER
namespace Konscious.Security.Cryptography;

using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Buffers.Binary;

internal static class Argon2CoreIntrinsics
{
    public static void XorLanes(ReadOnlySpan<Argon2Lane> lanes)
    {
        Debug.Assert(Avx2.IsSupported);

        var data = lanes[0][lanes[0].BlockCount - 1].Span;
        var dataVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(data);

        foreach (var lane in lanes[1..])
        {
            var block = lane[lane.BlockCount - 1].Span;

            if (BitConverter.IsLittleEndian)
            {
                var blockVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(block);
                for (int i = 0; i < 32; i++)
                {
                    Avx2.Xor(dataVectors[i], blockVectors[i]);
                }
            }
            else
            {
                for (var b = 0; b < 128; ++b)
                {
                    block[b] = BinaryPrimitives.ReverseEndianness(block[b]);

                    data[b] ^= block[b];
                }
            }
        }
    }

    public static void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refBlock, ReadOnlySpan<ulong> prevBlock)
    {
        Debug.Assert(Avx2.IsSupported);
        Debug.Assert(dest.Length == 128);

        Span<ulong> state = stackalloc ulong[dest.Length];
        Span<Vector256<ulong>> stateVectors = MemoryMarshal.Cast<ulong, Vector256<ulong>>(state);
        ref Vector256<ulong> refState = ref MemoryMarshal.GetReference(stateVectors);

        ref Vector256<ulong> refB = ref Unsafe.As<ulong, Vector256<ulong>>(ref MemoryMarshal.GetReference(refBlock));
        ref Vector256<ulong> refPrev = ref Unsafe.As<ulong,Vector256<ulong>>(ref MemoryMarshal.GetReference(prevBlock));
        ref Vector256<ulong> refDest = ref Unsafe.As<ulong, Vector256<ulong>>(ref MemoryMarshal.GetReference(dest));

        for (var n = 0; n < stateVectors.Length; ++n)
        {
            Unsafe.Add(ref refState, n) = Avx2.Xor(Unsafe.Add(ref refB, n), Unsafe.Add(ref refPrev, n));
            Unsafe.Add(ref refDest, n) = Avx2.Xor(Unsafe.Add(ref refState, n), Unsafe.Add(ref refDest, n));
        }

        //ModifiedBlake2Intrinsics.DoRoundColumns(stateVectors[..16]);
        //ModifiedBlake2Intrinsics.DoRoundColumns(stateVectors[16..]);

        //ModifiedBlake2Intrinsics.DoRoundRows(stateVectors);
        //ModifiedBlake2Intrinsics.DoRoundRows(stateVectors[8..]);

        //ModifiedBlake2Intrinsics.ReOrder(stateVectors[..16]);
        //ModifiedBlake2Intrinsics.ReOrder(stateVectors[16..]);

        for (int i = 0; i < 4; i++)
        {
            ModifiedBlake2Intrinsics.BLAKE2_ROUND_1(ref stateVectors[8 * i + 0], ref stateVectors[8 * i + 4], ref stateVectors[8 * i + 1], ref stateVectors[8 * i + 5], ref stateVectors[8 * i + 2], ref stateVectors[8 * i + 6], ref stateVectors[8 * i + 3], ref stateVectors[8 * i + 7]);
        }

        for (int i = 0; i < 4; i++)
        {
            ModifiedBlake2Intrinsics.BLAKE2_ROUND_2(ref stateVectors[0 + i], ref stateVectors[4 + i], ref stateVectors[8 + i], ref stateVectors[12 + i], ref stateVectors[16 + i], ref stateVectors[20 + i], ref stateVectors[24 + i], ref stateVectors[28 + i]);
        }

        for (int i = 0; i < stateVectors.Length; i++)
        {
            Unsafe.Add(ref refDest, i) = Avx2.Xor(Unsafe.Add(ref refDest, i), Unsafe.Add(ref refState, i));
        }
    }
}

#endif
