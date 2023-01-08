#if NET6_0_OR_GREATER
namespace Konscious.Security.Cryptography
{
    using System;
    using System.Diagnostics;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Runtime.Intrinsics;
    using System.Runtime.Intrinsics.X86;

    internal class Blake2bSimd : Blake2bBase
    {
        public Blake2bSimd(int HashBytes)
            : base(HashBytes)
        {
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public override void Compress(bool isFinal)
        {
            Compress(isFinal, Hash, DataBuffer, TotalSegmentsLow, TotalSegmentsHigh);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Compress(bool isFinal, Span<ulong> hashBuffer, ReadOnlySpan<byte> dataBuffer, ulong totalSegmentsLow, ulong totalSegmentsHigh)
        {
            Debug.Assert(dataBuffer.Length >= 128);
            Debug.Assert(hashBuffer.Length >= 8);

            unchecked
            {
                Vector256<byte> r24 = Vector256.Create((byte)3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
                Vector256<byte> r16 = Vector256.Create((byte)2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
               
                // TODO: moving this to the bottom causes a 2x slow down?
                ref ulong m = ref Unsafe.As<byte,ulong>(ref MemoryMarshal.GetReference(dataBuffer));

                ref ulong hash = ref MemoryMarshal.GetReference<ulong>(hashBuffer);

                var r_14 = isFinal ? ulong.MaxValue : 0;
                var t_0 = Vector256.Create(totalSegmentsLow, totalSegmentsHigh, r_14, 0);

                Vector256<ulong> row1 = VectorExtensions.LoadUnsafeVector256(ref hash);
                Vector256<ulong> row2 = VectorExtensions.LoadUnsafeVector256(ref hash, (nuint)Vector256<ulong>.Count);
                Vector256<ulong> row3 = Vector256.Create(
                    (ulong)0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL);
                Vector256<ulong> row4 = Vector256.Create((ulong)0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL);
                row4 = Avx2.Xor(row4, t_0);

                Vector256<ulong> orig_1 = row1;
                Vector256<ulong> orig_2 = row2;

                #region Rounds
                //ROUND 1
                var m0 = VectorExtensions.BroadcastVector128ToVector256(ref m);
                var m1 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count));
                var m2 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 2));
                var m3 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 3));

                var t0 = Avx2.UnpackLow(m0, m1);
                var t1 = Avx2.UnpackLow(m2, m3);
                var b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m0, m1);
                t1 = Avx2.UnpackHigh(m2, m3);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                var m4 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 4));
                var m5 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 5));
                var m6 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 6));
                var m7 = VectorExtensions.BroadcastVector128ToVector256(ref Unsafe.Add(ref m, Vector128<ulong>.Count * 7));

                t0 = Avx2.UnpackLow(m7, m4);
                t1 = Avx2.UnpackLow(m5, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m7, m4);
                t1 = Avx2.UnpackHigh(m5, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 2
                t0 = Avx2.UnpackLow(m7, m2);
                t1 = Avx2.UnpackHigh(m4, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m5, m4);
                t1 = Avx2.AlignRight(m3, m7, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackHigh(m2, m0);
                t1 = Avx2.Blend(m0.AsUInt32(), m5.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.AlignRight(m6, m1, 8);
                t1 = Avx2.Blend(m1.AsUInt32(), m3.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 3
                t0 = Avx2.AlignRight(m6, m5, 8);
                t1 = Avx2.UnpackHigh(m2, m7);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m4, m0);
                t1 = Avx2.Blend(m1.AsUInt32(), m6.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.AlignRight(m5, m4, 8);
                t1 = Avx2.UnpackHigh(m1, m3);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m2, m7);
                t1 = Avx2.Blend(m3.AsUInt32(), m0.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 4
                t0 = Avx2.UnpackHigh(m3, m1);
                t1 = Avx2.UnpackHigh(m6, m5);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m4, m0);
                t1 = Avx2.UnpackLow(m6, m7);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.AlignRight(m1, m7, 8);
                t1 = Avx2.Shuffle(m2.AsUInt32(), 0b_01_00_11_10).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m4, m3);
                t1 = Avx2.UnpackLow(m5, m0);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 5
                t0 = Avx2.UnpackHigh(m4, m2);
                t1 = Avx2.UnpackLow(m1, m5);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.Blend(m0.AsUInt32(), m3.AsUInt32(), 0b_1100_1100).AsUInt64();
                t1 = Avx2.Blend(m2.AsUInt32(), m7.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.AlignRight(m7, m1, 8);
                t1 = Avx2.AlignRight(m3, m5, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m6, m0);
                t1 = Avx2.UnpackLow(m6, m4);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 6
                t0 = Avx2.UnpackLow(m1, m3);
                t1 = Avx2.UnpackLow(m0, m4);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m6, m5);
                t1 = Avx2.UnpackHigh(m5, m1);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.AlignRight(m2, m0, 8);
                t1 = Avx2.UnpackHigh(m3, m7);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m4, m6);
                t1 = Avx2.AlignRight(m7, m2, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 7
                t0 = Avx2.Blend(m6.AsUInt32(), m0.AsUInt32(), 0b_1100_1100).AsUInt64();
                t1 = Avx2.UnpackLow(m7, m2);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m2, m7);
                t1 = Avx2.AlignRight(m5, m6, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackLow(m4, m0);
                t1 = Avx2.Blend(m3.AsUInt32(), m4.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m5, m3);
                t1 = Avx2.Shuffle(m1.AsUInt32(), 0b_01_00_11_10).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 8
                t0 = Avx2.UnpackHigh(m6, m3);
                t1 = Avx2.Blend(m6.AsUInt32(), m1.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.AlignRight(m7, m5, 8);
                t1 = Avx2.UnpackHigh(m0, m4);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.Blend(m1.AsUInt32(), m2.AsUInt32(), 0b_1100_1100).AsUInt64();
                t1 = Avx2.AlignRight(m4, m7, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m5, m0);
                t1 = Avx2.UnpackLow(m2, m3);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 9
                t0 = Avx2.UnpackLow(m3, m7);
                t1 = Avx2.AlignRight(m0, m5, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m7, m4);
                t1 = Avx2.AlignRight(m4, m1, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackLow(m5, m6);
                t1 = Avx2.UnpackHigh(m6, m0);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.AlignRight(m1, m2, 8);
                t1 = Avx2.AlignRight(m2, m3, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 10
                t0 = Avx2.UnpackLow(m5, m4);
                t1 = Avx2.UnpackHigh(m3, m0);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m1, m2);
                t1 = Avx2.Blend(m3.AsUInt32(), m2.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackHigh(m6, m7);
                t1 = Avx2.UnpackHigh(m4, m1);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.Blend(m0.AsUInt32(), m5.AsUInt32(), 0b_1100_1100).AsUInt64();
                t1 = Avx2.UnpackLow(m7, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 11
                t0 = Avx2.UnpackLow(m0, m1);
                t1 = Avx2.UnpackLow(m2, m3);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m0, m1);
                t1 = Avx2.UnpackHigh(m2, m3);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackLow(m7, m4);
                t1 = Avx2.UnpackLow(m5, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackHigh(m7, m4);
                t1 = Avx2.UnpackHigh(m5, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 12
                t0 = Avx2.UnpackLow(m7, m2);
                t1 = Avx2.UnpackHigh(m4, m6);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.UnpackLow(m5, m4);
                t1 = Avx2.AlignRight(m3, m7, 8);
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Avx2.UnpackHigh(m2, m0);
                t1 = Avx2.Blend(m0.AsUInt32(), m5.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G1(r24, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Avx2.AlignRight(m6, m1, 8);
                t1 = Avx2.Blend(m1.AsUInt32(), m3.AsUInt32(), 0b_1100_1100).AsUInt64();
                b0 = Avx2.Blend(t0.AsUInt32(), t1.AsUInt32(), 0b_1111_0000).AsUInt64();

                G2(r16, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);
                #endregion

                row1 = Avx2.Xor(row1, row3);
                row2 = Avx2.Xor(row2, row4);
                row1 = Avx2.Xor(row1, orig_1);
                row2 = Avx2.Xor(row2, orig_2);

                row1.StoreUnsafe(ref hash);
                row2.StoreUnsafe(ref hash, (nuint)Vector256<ulong>.Count);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Diagonalize(ref Vector256<ulong> row1, ref Vector256<ulong> row3, ref Vector256<ulong> row4)
        {
            unchecked
            {
                //     +-------------------+
                //     |  0 |  1 |  2 |  3 |
                //     +-------------------+
                //     |  8 |  9 | 10 | 11 |
                //     +-------------------+
                //     | 12 | 13 | 14 | 15 |
                //     +-------------------+
                //         --->
                //     +-------------------+
                //     |  3 |  0 |  1 |  2 |
                //     +-------------------+
                //     |  9 | 10 | 11 |  8 |
                //     +-------------------+
                //     | 14 | 15 | 12 | 13 |
                //     +-------------------+

                row1 = Avx2.Permute4x64(row1, 0b_10_01_00_11);
                row3 = Avx2.Permute4x64(row3, 0b_00_11_10_01);
                row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G1(Vector256<byte> r24, ref Vector256<ulong> row1, ref Vector256<ulong> row2, ref Vector256<ulong> row3, ref Vector256<ulong> row4, Vector256<ulong> b0)
        {
            unchecked
            {
                row1 = Avx2.Add(Avx2.Add(row1, b0), row2);
                row4 = Avx2.Xor(row4, row1);
                row4 = Avx2.Shuffle(row4.AsUInt32(), 0b_10_11_00_01).AsUInt64();

                row3 = Avx2.Add(row3, row4);
                row2 = Avx2.Xor(row2, row3);
                row2 = Avx2.Shuffle(row2.AsByte(), r24).AsUInt64();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G2(Vector256<byte> r16, ref Vector256<ulong> row1, ref Vector256<ulong> row2, ref Vector256<ulong> row3, ref Vector256<ulong> row4, Vector256<ulong> b0)
        {
            unchecked
            {
                row1 = Avx2.Add(Avx2.Add(row1, b0), row2);
                row4 = Avx2.Xor(row4, row1);
                row4 = Avx2.Shuffle(row4.AsByte(), r16).AsUInt64();

                row3 = Avx2.Add(row3, row4);
                row2 = Avx2.Xor(row2, row3);
                row2 = Avx2.Xor(Avx2.ShiftRightLogical(row2, 63), Avx2.Add(row2, row2));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Undiagonalize(ref Vector256<ulong> row1, ref Vector256<ulong> row3, ref Vector256<ulong> row4)
        {
            unchecked
            {
                //     +-------------------+
                //     |  3 |  0 |  1 |  2 |
                //     +-------------------+
                //     |  9 | 10 | 11 |  8 |
                //     +-------------------+
                //     | 14 | 15 | 12 | 13 |
                //     +-------------------+
                //         --->
                //     +-------------------+
                //     |  0 |  1 |  2 |  3 |
                //     +-------------------+
                //     |  8 |  9 | 10 | 11 |
                //     +-------------------+
                //     | 12 | 13 | 14 | 15 |
                //     +-------------------+

                row1 = Avx2.Permute4x64(row1, 0b_00_11_10_01);
                row3 = Avx2.Permute4x64(row3, 0b_10_01_00_11);
                row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
            }
        }
    }

    internal static class VectorExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector128<T> LoadUnsafeVector128<T>(ref T source)
                where T : struct
        {
            return Unsafe.ReadUnaligned<Vector128<T>>(ref Unsafe.As<T, byte>(ref source));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> LoadUnsafeVector256<T>(ref T source)
                where T : struct
        {
            return Unsafe.ReadUnaligned<Vector256<T>>(ref Unsafe.As<T, byte>(ref source));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> LoadUnsafeVector256<T>(ref T source, nuint elementOffset)
            where T : struct
        {
            source = ref Unsafe.Add(ref source, (nint)elementOffset);
            return Unsafe.ReadUnaligned<Vector256<T>>(ref Unsafe.As<T, byte>(ref source));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void StoreUnsafe<T>(this Vector256<T> source, ref T pdestination)
                where T : struct
        {
            Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref pdestination), source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void StoreUnsafe<T>(this Vector256<T> source, ref T Tdestination, nuint elementOffset)
            where T : struct
        {
            Tdestination = ref Unsafe.Add(ref Tdestination, (nint)elementOffset);
            Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref Tdestination), source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Vector256<T> BroadcastVector128ToVector256<T>(ref T ptr) where T : struct
        {
            var vector = Unsafe.ReadUnaligned<Vector128<T>>(ref Unsafe.As<T, byte>(ref ptr));
            Vector256<T> result = vector.ToVector256Unsafe();
            return result.WithUpper(vector);
        }
    }
}
#endif