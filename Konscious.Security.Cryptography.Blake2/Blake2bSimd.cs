#if NETCOREAPP3_1_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace Konscious.Security.Cryptography
{
    using System;
    using System.Buffers.Binary;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Runtime.Intrinsics;
    using System.Runtime.Intrinsics.X86;

    internal class Blake2bSimd : Blake2bBase
    {
        private static ReadOnlySpan<byte> rormask => new byte[] {
            3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, //r24
			2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9  //r16
		};

        public Blake2bSimd(int HashBytes)
            : base(HashBytes)
        {
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        //[SkipLocalsInit]
        public override void Compress(bool isFinal)
        {
            unchecked
            {
                // TODO inline
                ref byte prm = ref MemoryMarshal.GetReference(rormask);

                Vector256<byte> r24 = VectorExtensions.LoadUnsafeVector256(ref prm);
                Vector256<byte> r16 = VectorExtensions.LoadUnsafeVector256(ref prm, (nuint)Vector256<byte>.Count);

                Span<ulong> internalState = stackalloc ulong[16];
                ref ulong m = ref MemoryMarshal.GetReference(internalState);
                
                Vector256<ulong> row1;
                Vector256<ulong> row2;
                Vector256<ulong> row3;
                Vector256<ulong> row4;

                ref ulong hash = ref MemoryMarshal.GetReference<ulong>(Hash);
                ref ulong iv = ref MemoryMarshal.GetReference<ulong>(Blake2Constants.IV);

                row1 = VectorExtensions.LoadUnsafeVector256(ref hash);
                row2 = VectorExtensions.LoadUnsafeVector256(ref hash, (nuint)Vector256<ulong>.Count);
                row3 = VectorExtensions.LoadUnsafeVector256(ref iv);
                row4 = VectorExtensions.LoadUnsafeVector256(ref iv, (nuint)Vector256<ulong>.Count);

                var r_14 = isFinal ? ulong.MaxValue : 0;
                var t_0 = Vector256.Create(TotalSegmentsLow, TotalSegmentsHigh, r_14, 0);
                row4 = Avx2.Xor(row4, t_0);

                MemoryMarshal.Cast<byte, ulong>(DataBuffer).CopyTo(internalState);

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
        private static unsafe void Diagonalize(ref Vector256<ulong> row1, ref Vector256<ulong> row3, ref Vector256<ulong> row4)
        {
            unchecked
            {
                row1 = Avx2.Permute4x64(row1, 0b_10_01_00_11);
                row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
                row3 = Avx2.Permute4x64(row3, 0b_00_11_10_01);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void G1(Vector256<byte> r24, ref Vector256<ulong> row1, ref Vector256<ulong> row2, ref Vector256<ulong> row3, ref Vector256<ulong> row4, Vector256<ulong> b0)
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
        private static unsafe void G2(Vector256<byte> r16, ref Vector256<ulong> row1, ref Vector256<ulong> row2, ref Vector256<ulong> row3, ref Vector256<ulong> row4, Vector256<ulong> b0)
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
        private static unsafe void Undiagonalize(ref Vector256<ulong> row1, ref Vector256<ulong> row3, ref Vector256<ulong> row4)
        {
            unchecked
            {
                row1 = Avx2.Permute4x64(row1, 0b_00_11_10_01);
                row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
                row3 = Avx2.Permute4x64(row3, 0b_10_01_00_11);
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
        public static void StoreUnsafe<T>(this Vector256<T> source, ref T destination)
                where T : struct
        {
            Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref destination), source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void StoreUnsafe<T>(this Vector256<T> source, ref T destination, nuint elementOffset)
            where T : struct
        {
            destination = ref Unsafe.Add(ref destination, (nint)elementOffset);
            Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref destination), source);
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