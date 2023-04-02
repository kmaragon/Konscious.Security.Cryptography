#if NET6_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Diagnostics;

namespace Konscious.Security.Cryptography;

// SIMD algorithm described in https://eprint.iacr.org/2012/275.pdf

internal class ModifiedBlake2Avx2 : ModifiedBlake2Base
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
    private static Vector256<ulong> rotr32(Vector256<ulong> x)
    {
        return Avx2.Shuffle(x.AsUInt32(), 0b_10_11_00_01).AsUInt64();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> rotr24(Vector256<ulong> x)
    {
        var r24 = Vector256.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);

        return Avx2.Shuffle(x.AsByte(), r24).AsUInt64();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> rotr16(Vector256<ulong> x)
    {
        var r16 = Vector256.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);

        return Avx2.Shuffle(x.AsByte(), r16).AsUInt64();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<ulong> rotr63(Vector256<ulong> x)
    {
        return Avx2.Or(Avx2.ShiftLeftLogical(x, 1), Avx2.ShiftRightLogical(x, 63));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void G1Avx2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        Vector256<ulong> ml;

        // First block
        ml = Avx2.Multiply(A0.AsUInt32(), B0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A0 = Avx2.Add(A0, Avx2.Add(B0, ml));
        D0 = Avx2.Xor(D0, A0);
        D0 = rotr32(D0);

        ml = Avx2.Multiply(C0.AsUInt32(), D0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C0 = Avx2.Add(C0, Avx2.Add(D0, ml));
        B0 = Avx2.Xor(B0, C0);
        B0 = rotr24(B0);

        // Second block
        ml = Avx2.Multiply(A1.AsUInt32(), B1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A1 = Avx2.Add(A1, Avx2.Add(B1, ml));
        D1 = Avx2.Xor(D1, A1);
        D1 = rotr32(D1);

        ml = Avx2.Multiply(C1.AsUInt32(), D1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C1 = Avx2.Add(C1, Avx2.Add(D1, ml));
        B1 = Avx2.Xor(B1, C1);
        B1 = rotr24(B1);
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void G2Avx2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        Vector256<ulong> ml = Avx2.Multiply(A0.AsUInt32(), B0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A0 = Avx2.Add(Avx2.Add(A0, B0), ml);
        D0 = Avx2.Xor(D0, A0);
        D0 = rotr16(D0);

        ml = Avx2.Multiply(C0.AsUInt32(), D0.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C0 = Avx2.Add(Avx2.Add(C0, D0), ml);
        B0 = Avx2.Xor(B0, C0);
        B0 = rotr63(B0);

        ml = Avx2.Multiply(A1.AsUInt32(), B1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        A1 = Avx2.Add(Avx2.Add(A1, B1), ml);
        D1 = Avx2.Xor(D1, A1);
        D1 = rotr16(D1);

        ml = Avx2.Multiply(C1.AsUInt32(), D1.AsUInt32());
        ml = Avx2.Add(ml, ml);
        C1 = Avx2.Add(Avx2.Add(C1, D1), ml);
        B1 = Avx2.Xor(B1, C1);
        B1 = rotr63(B1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Diagonalize1(ref Vector256<ulong> B0, ref Vector256<ulong> C0, ref Vector256<ulong> D0, ref Vector256<ulong> B1, ref Vector256<ulong> C1, ref Vector256<ulong> D1)
    {
        B0 = Avx2.Permute4x64(B0, 0b_00_11_10_01);
        C0 = Avx2.Permute4x64(C0, 0b_01_00_11_10);
        D0 = Avx2.Permute4x64(D0, 0b_10_01_00_11);

        B1 = Avx2.Permute4x64(B1, 0b_00_11_10_01);
        C1 = Avx2.Permute4x64(C1, 0b_01_00_11_10);
        D1 = Avx2.Permute4x64(D1, 0b_10_01_00_11);
    }

    // DIAGONALIZE_2
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Diagonalize2(ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        var tmp1 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0xCC).AsUInt64();
        var tmp2 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0x33).AsUInt64();
        B1 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        B0 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);

        tmp1 = C0;
        C0 = C1;
        C1 = tmp1;

        tmp1 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0xCC).AsUInt64();
        tmp2 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0x33).AsUInt64();
        D0 = Avx2.Permute4x64(tmp1, 0b_10_11_00_01);
        D1 = Avx2.Permute4x64(tmp2, 0b_10_11_00_01);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Undiagonalize1(ref Vector256<ulong> B0, ref Vector256<ulong> C0, ref Vector256<ulong> D0, ref Vector256<ulong> B1, ref Vector256<ulong> C1, ref Vector256<ulong> D1)
    {
        B0 = Avx2.Permute4x64(B0, 0b_10_01_00_11);
        C0 = Avx2.Permute4x64(C0, 0b_01_00_11_10);
        D0 = Avx2.Permute4x64(D0, 0b_00_11_10_01);

        B1 = Avx2.Permute4x64(B1, 0b_10_01_00_11);
        C1 = Avx2.Permute4x64(C1, 0b_01_00_11_10);
        D1 = Avx2.Permute4x64(D1, 0b_00_11_10_01);
    }

    public static void Undiagonalize2(ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        var tmp1 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0xCC).AsUInt64();
        var tmp2 = Avx2.Blend(B0.AsUInt32(), B1.AsUInt32(), 0x33).AsUInt64();
        B0 = Avx2.Permute4x64(tmp1.AsUInt64(), 0b_10_11_00_01);
        B1 = Avx2.Permute4x64(tmp2.AsUInt64(), 0b_10_11_00_01);

        tmp1 = C0;
        C0 = C1;
        C1 = tmp1;

        tmp1 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0x33).AsUInt64();
        tmp2 = Avx2.Blend(D0.AsUInt32(), D1.AsUInt32(), 0xCC).AsUInt64();
        D0 = Avx2.Permute4x64(tmp1.AsUInt64(), 0b_10_11_00_01);
        D1 = Avx2.Permute4x64(tmp2.AsUInt64(), 0b_10_11_00_01);
    }

    public static void Blake2Round1(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        G1Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize1(ref B0, ref C0, ref D0, ref B1, ref C1, ref D1);

        G1Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize1(ref B0, ref C0, ref D0, ref B1, ref C1, ref D1);
    }

    public static void Blake2Round2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        G1Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize2(ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        G1Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2Avx2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize2(ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
    }

    //public unsafe static void DoRoundRows(ulong *v, int i)
    //{
    //    i *= 2;
    //    ModifiedG(v,      i, i + 32, i + 64, i +  96);
    //    ModifiedG(v, i +  1, i + 33, i + 65, i +  97);
    //    ModifiedG(v, i + 16, i + 48, i + 80, i + 112);
    //    ModifiedG(v, i + 17, i + 49, i + 81, i + 113);
    //    ModifiedG(v,      i, i + 33, i + 80, i + 113);
    //    ModifiedG(v, i +  1, i + 48, i + 81, i +  96);
    //    ModifiedG(v, i + 16, i + 49, i + 64, i +  97);
    //    ModifiedG(v, i + 17, i + 32, i + 65, i + 112);
    //}
    
    public override void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refBlock, ReadOnlySpan<ulong> prevBlock)
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

        for (int i = 0; i < 4; i++)
        {
            Blake2Round1(ref stateVectors[8 * i + 0], ref stateVectors[8 * i + 4], ref stateVectors[8 * i + 1], ref stateVectors[8 * i + 5], ref stateVectors[8 * i + 2], ref stateVectors[8 * i + 6], ref stateVectors[8 * i + 3], ref stateVectors[8 * i + 7]);
        }

        for (int i = 0; i < 4; i++)
        {
            Blake2Round2(ref stateVectors[0 + i], ref stateVectors[4 + i], ref stateVectors[8 + i], ref stateVectors[12 + i], ref stateVectors[16 + i], ref stateVectors[20 + i], ref stateVectors[24 + i], ref stateVectors[28 + i]);
        }

        for (int i = 0; i < stateVectors.Length; i++)
        {
            Unsafe.Add(ref refDest, i) = Avx2.Xor(Unsafe.Add(ref refDest, i), Unsafe.Add(ref refState, i));
        }
    }

    public override bool IsSupported => Avx2.IsSupported;
}
#endif