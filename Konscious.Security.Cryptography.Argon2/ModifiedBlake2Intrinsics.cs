#if NET6_0_OR_GREATER
#pragma warning disable CA1801 // Review unused parameters
#pragma warning disable IDE0060 // Remove unused parameter
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Threading.Tasks;

namespace Konscious.Security.Cryptography;

// SIMD algorithm described in https://eprint.iacr.org/2012/275.pdf

internal static class ModifiedBlake2Intrinsics
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
    public static unsafe void G1_AVX2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
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
    public static void G2_AVX2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
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
    public static void Diagonalize1(ref Vector256<ulong> A0, ref Vector256<ulong> B0, ref Vector256<ulong> C0, ref Vector256<ulong> D0, ref Vector256<ulong> A1, ref Vector256<ulong> B1, ref Vector256<ulong> C1, ref Vector256<ulong> D1)
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
    public static void Diagonalize2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
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
    public static void Undiagonalize1(ref Vector256<ulong> A0, ref Vector256<ulong> B0, ref Vector256<ulong> C0, ref Vector256<ulong> D0, ref Vector256<ulong> A1, ref Vector256<ulong> B1, ref Vector256<ulong> C1, ref Vector256<ulong> D1)
    {
        B0 = Avx2.Permute4x64(B0, 0b_10_01_00_11);
        C0 = Avx2.Permute4x64(C0, 0b_01_00_11_10);
        D0 = Avx2.Permute4x64(D0, 0b_00_11_10_01);

        B1 = Avx2.Permute4x64(B1, 0b_10_01_00_11);
        C1 = Avx2.Permute4x64(C1, 0b_01_00_11_10);
        D1 = Avx2.Permute4x64(D1, 0b_00_11_10_01);
    }

    public static void Undiagonalize2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
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

    public static void BLAKE2_ROUND_1(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        G1_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);

        G1_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize1(ref A0, ref B0, ref C0, ref D0, ref A1, ref B1, ref C1, ref D1);
    }

    public static void BLAKE2_ROUND_2(ref Vector256<ulong> A0, ref Vector256<ulong> A1, ref Vector256<ulong> B0, ref Vector256<ulong> B1, ref Vector256<ulong> C0, ref Vector256<ulong> C1, ref Vector256<ulong> D0, ref Vector256<ulong> D1)
    {
        G1_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Diagonalize2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        G1_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
        G2_AVX2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);

        Undiagonalize2(ref A0, ref A1, ref B0, ref B1, ref C0, ref C1, ref D0, ref D1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe static void ModifiedG(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        var r24 = Vector256.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
        var r16 = Vector256.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);

        Vector256<ulong> t = Avx2.Multiply(a.AsUInt32(), b.AsUInt32());
        a = Avx2.Add(Avx2.Add(a, b), Avx2.Add(t, t));

        d = Avx2.Shuffle((Avx2.Xor(d, a)).AsUInt32(), 0b_10_11_00_01).AsUInt64();

        t = Avx2.Multiply(c.AsUInt32(), d.AsUInt32());
        c = Avx2.Add(Avx2.Add(c, d), Avx2.Add(t, t));

        b = Avx2.Shuffle(Avx2.Xor(b, c).AsByte(), r24).AsUInt64();

        t = Avx2.Multiply(a.AsUInt32(), b.AsUInt32());
        a = Avx2.Add(Avx2.Add(a, b), Avx2.Add(t, t));

        d = Avx2.Shuffle(Avx2.Xor(d, a).AsByte(), r16).AsUInt64();

        t = Avx2.Multiply(c.AsUInt32(), d.AsUInt32());
        c = Avx2.Add(Avx2.Add(c, d), Avx2.Add(t, t));

        b= Avx2.Xor(b, c);
        b = Avx2.Or(Avx2.ShiftLeftLogical(b, 1), Avx2.ShiftRightLogical(b, 63));
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
    public static void DoRoundColumns(Span<Vector256<ulong>> vectors)
    {
        // Takes vectors in the form
        // [<0,1,2,3>, <4,5,6,7>, <8,9...]
        // Takes groups of 4 and transposes them to
        // [<0,16,32,48>, <1,17,33,49>, <2,18...]
        // Shuffles them and returns the Vector span.

        Vector256<ulong> x_0 = vectors[0];
        Vector256<ulong> x_1 = vectors[4];
        Vector256<ulong> x_2 = vectors[8];
        Vector256<ulong> x_3 = vectors[12];

        Vector256<ulong> x_4 = vectors[1];
        Vector256<ulong> x_5 = vectors[5];
        Vector256<ulong> x_6 = vectors[9];
        Vector256<ulong> x_7 = vectors[13];

        Vector256<ulong> x_8 = vectors[2];
        Vector256<ulong> x_9 = vectors[6];
        Vector256<ulong> x_10 = vectors[10];
        Vector256<ulong> x_11 = vectors[14];

        Vector256<ulong> x_12 = vectors[3];
        Vector256<ulong> x_13 = vectors[7];
        Vector256<ulong> x_14 = vectors[11];
        Vector256<ulong> x_15 = vectors[15];

        Transpose(ref x_0, ref x_1, ref x_2, ref x_3);
        Transpose(ref x_4, ref x_5, ref x_6, ref x_7);
        Transpose(ref x_8, ref x_9, ref x_10, ref x_11);
        Transpose(ref x_12, ref x_13, ref x_14, ref x_15);

        ModifiedG(ref x_0, ref x_4, ref x_8, ref x_12);
        ModifiedG(ref x_1, ref x_5, ref x_9, ref x_13);
        ModifiedG(ref x_2, ref x_6, ref x_10, ref x_14);
        ModifiedG(ref x_3, ref x_7, ref x_11, ref x_15);

        ModifiedG(ref x_0, ref x_5, ref x_10, ref x_15);
        ModifiedG(ref x_1, ref x_6, ref x_11, ref x_12);
        ModifiedG(ref x_2, ref x_7, ref x_8, ref x_13);
        ModifiedG(ref x_3, ref x_4, ref x_9, ref x_14);

        vectors[0] = x_0;
        vectors[1] = x_1;
        vectors[2] = x_2;
        vectors[3] = x_3;
        vectors[4] = x_4;
        vectors[5] = x_5;
        vectors[6] = x_6;
        vectors[7] = x_7;
        vectors[8] = x_8;
        vectors[9] = x_9;
        vectors[10] = x_10;
        vectors[11] = x_11;
        vectors[12] = x_12;
        vectors[13] = x_13;
        vectors[14] = x_14;
        vectors[15] = x_15;
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DoRoundRows(Span<Vector256<ulong>> vectors)
    {
        // Takes vectors in the form
        // [<0,16,32,48>, <1,17,33,49>, <2,18...] ...
        // Takes every other vector for 0-6, 1-7, 16-22, 17-23 and transposes them to
        // [<0,2,4,6>, <16,18,20,22>, <32,34...],
        // [<1,3,5,7>, <17,19,21,23>, <33,35..],
        // [<64,66,68,70>, <80,82,84,86>, <96,98...] ...
        // Shuffles the vectors and then returns them.

        Vector256<ulong> x_0 = vectors[0];
        Vector256<ulong> x_2 = vectors[2];
        Vector256<ulong> x_4 = vectors[4];
        Vector256<ulong> x_6 = vectors[6];

        Vector256<ulong> x_1 = vectors[1];
        Vector256<ulong> x_3 = vectors[3];
        Vector256<ulong> x_5 = vectors[5];
        Vector256<ulong> x_7 = vectors[7];

        Vector256<ulong> x_8 = vectors[16];
        Vector256<ulong> x_10 = vectors[18];
        Vector256<ulong> x_12 = vectors[20];
        Vector256<ulong> x_14 = vectors[22];

        Vector256<ulong> x_9 = vectors[17];
        Vector256<ulong> x_11 = vectors[19];
        Vector256<ulong> x_13 = vectors[21];
        Vector256<ulong> x_15 = vectors[23];

        Transpose(ref x_0, ref x_2, ref x_4, ref x_6);
        Transpose(ref x_1, ref x_3, ref x_5, ref x_7);
        Transpose(ref x_8, ref x_10, ref x_12, ref x_14);
        Transpose(ref x_9, ref x_11, ref x_13, ref x_15);

        ModifiedG(ref x_0, ref x_4, ref x_8, ref x_12);
        ModifiedG(ref x_1, ref x_5, ref x_9, ref x_13);
        ModifiedG(ref x_2, ref x_6, ref x_10, ref x_14);
        ModifiedG(ref x_3, ref x_7, ref x_11, ref x_15);

        ModifiedG(ref x_0, ref x_5, ref x_10, ref x_15);
        ModifiedG(ref x_1, ref x_6, ref x_11, ref x_12);
        ModifiedG(ref x_2, ref x_7, ref x_8, ref x_13);
        ModifiedG(ref x_3, ref x_4, ref x_9, ref x_14);

        vectors[0] = x_0;
        vectors[1] = x_1;
        vectors[2] = x_2;
        vectors[3] = x_3;
        vectors[4] = x_4;
        vectors[5] = x_5;
        vectors[6] = x_6;
        vectors[7] = x_7;
        vectors[16] = x_8;
        vectors[17] = x_9;
        vectors[18] = x_10;
        vectors[19] = x_11;
        vectors[20] = x_12;
        vectors[21] = x_13;
        vectors[22] = x_14;
        vectors[23] = x_15;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ReOrder(Span<Vector256<ulong>> data)
    {
        Debug.Assert(data.Length == 16);

        // Takes vectors in the form
        // data[0..8] = [<0,2,4,6>, <1,3,5,7>, <16,18,20,22>, <17,19,21,23>, <32,34,36,38>,  <33,35,37,39>, <48..., <49...]
        // data[8..16] = [<8,10,12,14>, <9,11,13,15>, <24..., <25..., <40..., <41..., <56..., <57...]
        // Interweave takes two vectors, re packs the numbers, store them in the buffer.
        // Buffer is then recopied to data.

        Span<Vector256<ulong>> buffer = stackalloc Vector256<ulong>[16];

        ref Vector256<ulong> ptr = ref MemoryMarshal.GetReference(buffer);
        ref Vector256<ulong> source = ref MemoryMarshal.GetReference(data);

        Interweave(ref source, ref ptr);
        Interweave(ref Unsafe.Add(ref source, 8), ref Unsafe.Add(ref ptr, 2));
        Interweave(ref Unsafe.Add(ref source, 2), ref Unsafe.Add(ref ptr, 4));
        Interweave(ref Unsafe.Add(ref source, 10), ref Unsafe.Add(ref ptr, 6));

        Interweave(ref Unsafe.Add(ref source, 4), ref Unsafe.Add(ref ptr, 8));
        Interweave(ref Unsafe.Add(ref source, 12), ref Unsafe.Add(ref ptr, 10));
        Interweave(ref Unsafe.Add(ref source, 6), ref Unsafe.Add(ref ptr, 12));
        Interweave(ref Unsafe.Add(ref source, 14), ref Unsafe.Add(ref ptr, 14));

        buffer.CopyTo(data);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Interweave(ref Vector256<ulong> source, ref Vector256<ulong> destination)
    {
        //     +-------------------+
        //     |  0 |  4 |  2 |  6 |
        //     +-------------------+
        //     |  1 |  5 |  3 |  7 |
        //     +-------------------+
        //         --->
        //     +-------------------+
        //     |  0 |  1 |  2 |  3 |
        //     +-------------------+
        //     |  4 |  5 |  6 |  7 |
        //     +-------------------+
        Vector256<ulong> low = Avx2.UnpackLow(source, Unsafe.Add(ref source, 1));
        Vector256<ulong> high = Avx2.UnpackHigh(source, Unsafe.Add(ref source, 1));

        destination = Avx2.Permute2x128(low, high, 0b_00_10_00_00);
        Unsafe.Add(ref destination, 1) = Avx2.Permute2x128(low, high, 0b_00_11_00_01);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Transpose(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        Vector256<ulong> w_0 = Avx2.UnpackLow(a, b);
        Vector256<ulong> w_1 = Avx2.UnpackHigh(a, b);
        Vector256<ulong> w_2 = Avx2.UnpackLow(c, d);
        Vector256<ulong> w_3 = Avx2.UnpackHigh(c, d);

        a = Avx2.Permute2x128(w_0, w_2, 0b_00_10_00_00);
        b = Avx2.Permute2x128(w_1, w_3, 0b_00_10_00_00);
        c = Avx2.Permute2x128(w_0, w_2, 0b_00_11_00_01);
        d = Avx2.Permute2x128(w_1, w_3, 0b_00_11_00_01);
    }
}
#pragma warning restore IDE0060 // Remove unused parameter
#pragma warning restore CA1801 // Review unused parameters
#endif
