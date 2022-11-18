#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Diagnostics;

namespace Konscious.Security.Cryptography;

// SIMD algorithm described in https://eprint.iacr.org/2012/275.pdf

internal static class ModifiedBlake2Intrinsics
{
    private static ReadOnlySpan<byte> rormask => new byte[] {
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, //r24
			2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9  //r16
		};

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
    private unsafe static void ModifiedG(ref Vector256<ulong> a, ref Vector256<ulong> b, ref Vector256<ulong> c, ref Vector256<ulong> d)
    {
        byte* prm = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(rormask));
        var r24 = Avx2.BroadcastVector128ToVector256(prm);
        var r16 = Avx2.BroadcastVector128ToVector256(prm + Vector128<byte>.Count);

        //var t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
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
    public static unsafe void DoRoundColumns(Span<Vector256<ulong>> vectors)
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
    public static unsafe void DoRoundRows(Span<Vector256<ulong>> vectors)
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
    public unsafe static void ReOrder(Span<Vector256<ulong>> data)
    {
        Debug.Assert(data.Length == 16);

        // Takes vectors in the form
        // data[0..8] = [<0,2,4,6>, <1,3,5,7>, <16,18,20,22>, <17,19,21,23>, <32,34,36,38>,  <33,35,37,39>, <48..., <49...]
        // data[8..16] = [<8,10,12,14>, <9,11,13,15>, <24..., <25..., <40..., <41..., <56..., <57...]
        // Interweave takes two vectors, re packs the numbers, store them in the buffer.
        // Buffer is then recopied to data.

        Span<Vector256<ulong>> buffer = stackalloc Vector256<ulong>[data.Length];
        fixed (Vector256<ulong>* buff = &buffer[0], source = &data[0])
        {
            Interweave(source + 0, buff + 0);
            Interweave(source + 8, buff + 2);
            Interweave(source + 2, buff + 4);
            Interweave(source + 10, buff + 6);

            Interweave(source + 4, buff + 8);
            Interweave(source + 12, buff + 10);
            Interweave(source + 6, buff + 12);
            Interweave(source + 14, buff + 14);

            buffer.CopyTo(data);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe static void Interweave(Vector256<ulong>* source, Vector256<ulong>* destination)
    {
        Vector256<ulong> low = Avx2.UnpackLow(*source, *(source + 1));
        Vector256<ulong> high = Avx2.UnpackHigh(*source, *(source + 1));

        *destination = Avx2.Permute2x128(low, high, 0b_00_10_00_00);
        *(destination + 1) = Avx2.Permute2x128(low, high, 0b_00_11_00_01);
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
#endif
