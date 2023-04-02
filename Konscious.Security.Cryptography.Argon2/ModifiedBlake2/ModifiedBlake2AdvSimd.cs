#if NET6_0_OR_GREATER

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics;
using System.Diagnostics;

namespace Konscious.Security.Cryptography;

internal class ModifiedBlake2AdvSimd : ModifiedBlake2Base
{
    //private unsafe static void ModifiedG(ulong* v, int a, int b, int c, int d)
    //{
    //    var t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
    //    v[a] = v[a] + v[b] + 2 * t;

    //    v[d] = Rotate(v[d] ^ v[a], 32);

    //    t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
    //    v[c] = v[c] + v[d] + 2 * t;

    //    v[b] = Rotate(v[b] ^ v[c], 24);

    //    t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
    //    v[a] = v[a] + v[b] + 2 * t;


    //    v[d] = Rotate(v[d] ^ v[a], 16);

    //    t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
    //    v[c] = v[c] + v[d] + 2 * t;

    //    v[b] = Rotate(v[b] ^ v[c], 63);
    //}
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> MultiplyLower32(Vector128<ulong> a, Vector128<ulong> b)
    {
        return AdvSimd.MultiplyWideningLower(AdvSimd.ExtractNarrowingLower(a), AdvSimd.ExtractNarrowingLower(b));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<ulong> Rotate(Vector128<ulong> x, byte y)
    {
        return AdvSimd.ShiftRightAndInsert(AdvSimd.ShiftLeftLogical(x, (byte)(64 - y)), x, y);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ModifiedG(ref Vector128<ulong> a, ref Vector128<ulong> b, ref Vector128<ulong> c,
        ref Vector128<ulong> d)
    {
        Vector128<ulong> t = MultiplyLower32(a, b);
        a = AdvSimd.Add(AdvSimd.Add(a, b), AdvSimd.Add(t, t));

        d = Rotate(AdvSimd.Xor(d, a), 32);

        t = MultiplyLower32(c, d);
        c = AdvSimd.Add(AdvSimd.Add(c, d), AdvSimd.Add(t, t));

        b = Rotate(AdvSimd.Xor(b, c), 24);

        t = MultiplyLower32(a, b);
        a = AdvSimd.Add(AdvSimd.Add(a, b), AdvSimd.Add(t, t));

        d = Rotate(AdvSimd.Xor(d, a), 16);

        t = MultiplyLower32(c, d);
        c = AdvSimd.Add(AdvSimd.Add(c, d), AdvSimd.Add(t, t));

        b = AdvSimd.Xor(b, c);
        b = AdvSimd.Or(AdvSimd.ShiftLeftLogical(b, 1), AdvSimd.ShiftRightLogical(b, 63));
    }

    //public unsafe static void DoRoundColumns(ulong *v, int i)
    //{
    //    i *= 16;
    //    ModifiedG(v,     i, i + 4,  i + 8, i + 12);
    //    ModifiedG(v, i + 1, i + 5,  i + 9, i + 13);
    //    ModifiedG(v, i + 2, i + 6, i + 10, i + 14);
    //    ModifiedG(v, i + 3, i + 7, i + 11, i + 15);
    //    ModifiedG(v,     i, i + 5, i + 10, i + 15);
    //    ModifiedG(v, i + 1, i + 6, i + 11, i + 12);
    //    ModifiedG(v, i + 2, i + 7,  i + 8, i + 13);
    //    ModifiedG(v, i + 3, i + 4,  i + 9, i + 14);
    //}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DoRoundColumns(Span<Vector128<ulong>> vectors)
    {
        // 8 times
        //    ModifiedG(v,     i, i + 4,  i + 8, i + 12);
        //    ModifiedG(v, i + 1, i + 5,  i + 9, i + 13);
        //    ModifiedG(v, i + 2, i + 6, i + 10, i + 14);
        //    ModifiedG(v, i + 3, i + 7, i + 11, i + 15);
        ModifiedG(ref vectors[0], ref vectors[2], ref vectors[4], ref vectors[6]);
        ModifiedG(ref vectors[1], ref vectors[3], ref vectors[5], ref vectors[7]);

        //
        // i + 5 is in vectors[2] high, i + 6 is in vectors[3] low
        // i + 15 is in vectors[7] high and i + 12 is in vectors[6] low
        //    ModifiedG(v,     i, i + 5, i + 10, i + 15);
        //    ModifiedG(v, i + 1, i + 6, i + 11, i + 12);
        //    ModifiedG(v, i + 2, i + 7,  i + 8, i + 13);
        //    ModifiedG(v, i + 3, i + 4,  i + 9, i + 14);
        var b_0 = AdvSimd.ExtractVector128(vectors[2], vectors[3], (byte)1);
        var b_1 = AdvSimd.ExtractVector128(vectors[3], vectors[2], (byte)1);
        var d_0 = AdvSimd.ExtractVector128(vectors[7], vectors[6], (byte)1);
        var d_1 = AdvSimd.ExtractVector128(vectors[6], vectors[7], (byte)1);

        ModifiedG(ref vectors[0], ref b_0, ref vectors[5], ref d_0);
        ModifiedG(ref vectors[1], ref b_1, ref vectors[4], ref d_1);
        vectors[2] = AdvSimd.ExtractVector128(b_1, b_0, (byte)1);
        vectors[3] = AdvSimd.ExtractVector128(b_0, b_1, (byte)1);
        vectors[6] = AdvSimd.ExtractVector128(d_0, d_1, (byte)1);
        vectors[7] = AdvSimd.ExtractVector128(d_1, d_0, (byte)1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DoRoundRows(Span<Vector128<ulong>> vectors)
    {
        //    ModifiedG(v,      i, i + 32, i + 64, i +  96);
        //    ModifiedG(v, i +  1, i + 33, i + 65, i +  97);
        ModifiedG(ref vectors[0], ref vectors[16], ref vectors[32], ref vectors[48]);

        //    ModifiedG(v, i + 16, i + 48, i + 80, i + 112);
        //    ModifiedG(v, i + 17, i + 49, i + 81, i + 113);
        ModifiedG(ref vectors[8], ref vectors[24], ref vectors[40], ref vectors[56]);
        
        //    ModifiedG(v,      i, i + 33, i + 80, i + 113);
        //    ModifiedG(v, i +  1, i + 48, i + 81, i +  96);
        //    ModifiedG(v, i + 16, i + 49, i + 64, i +  97);
        //    ModifiedG(v, i + 17, i + 32, i + 65, i + 112);
        var b_0 = AdvSimd.ExtractVector128(vectors[16], vectors[24], (byte)1);
        var b_1 = AdvSimd.ExtractVector128(vectors[24], vectors[16], (byte)1);
        var d_0 = AdvSimd.ExtractVector128(vectors[56], vectors[48], (byte)1);
        var d_1 = AdvSimd.ExtractVector128(vectors[48], vectors[56], (byte)1);
        
        ModifiedG(ref vectors[0], ref b_0, ref vectors[40], ref d_0);
        ModifiedG(ref vectors[8], ref b_1, ref vectors[32], ref d_1);
        
        vectors[16] = AdvSimd.ExtractVector128(b_1, b_0, (byte)1);
        vectors[24] = AdvSimd.ExtractVector128(b_0, b_1, (byte)1);
        vectors[48] = AdvSimd.ExtractVector128(d_0, d_1, (byte)1);
        vectors[56] = AdvSimd.ExtractVector128(d_1, d_0, (byte)1);
    }

    public override void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refBlock, ReadOnlySpan<ulong> prevBlock)
    {
        Span<ulong> state = stackalloc ulong[dest.Length];
        Span<Vector128<ulong>> stateVectors = MemoryMarshal.Cast<ulong, Vector128<ulong>>(state);
        ref Vector128<ulong> refState = ref MemoryMarshal.GetReference(stateVectors);
        
        ref Vector128<ulong> refB = ref Unsafe.As<ulong, Vector128<ulong>>(ref MemoryMarshal.GetReference(refBlock));
        ref Vector128<ulong> refPrev = ref Unsafe.As<ulong,Vector128<ulong>>(ref MemoryMarshal.GetReference(prevBlock));
        ref Vector128<ulong> refDest = ref Unsafe.As<ulong, Vector128<ulong>>(ref MemoryMarshal.GetReference(dest));
        
        for (var n = 0; n < stateVectors.Length; ++n)
        {
            Unsafe.Add(ref refState, n) = AdvSimd.Xor(Unsafe.Add(ref refB, n), Unsafe.Add(ref refPrev, n));
            Unsafe.Add(ref refDest, n) = AdvSimd.Xor(Unsafe.Add(ref refState, n), Unsafe.Add(ref refDest, n));
        }

        for (var i = 0; i < 8; ++i)
            DoRoundColumns(stateVectors.Slice(i * 8, 8));
        for (var i = 0; i < 8; ++i)
            DoRoundRows(stateVectors.Slice(i, 57));

        for (int i = 0; i < stateVectors.Length; i++)
        {
            Unsafe.Add(ref refDest, i) = AdvSimd.Xor(Unsafe.Add(ref refDest, i), Unsafe.Add(ref refState, i));
        }
    }
    
    public override bool IsSupported => AdvSimd.IsSupported;
}


#endif