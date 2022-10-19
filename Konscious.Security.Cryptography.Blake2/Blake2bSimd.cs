#if NETCOREAPP3_1_OR_GREATER
namespace Konscious.Security.Cryptography
{
    using System;
    using System.Numerics;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Runtime.Intrinsics;
    using System.Runtime.Intrinsics.X86;

    internal class Blake2bSimd : Blake2bBase
    {
        private static ReadOnlySpan<byte> rormask => new byte[] {
            3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, //r24
			2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9  //r16
		};

        public Blake2bSimd(int HashBytes)
            : base(HashBytes)
        {
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe override void Compress(bool isFinal)
        {
            unchecked
            {
                byte* prm = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(rormask));
                Vector256<byte> r24 = Avx2.BroadcastVector128ToVector256(prm);
                var r16 = Avx2.BroadcastVector128ToVector256(prm + Vector128<byte>.Count);

                ulong* m = stackalloc ulong[16];

                Vector256<ulong> v_0;
                Vector256<ulong> v_1;
                Vector256<ulong> v_2;
                Vector256<ulong> v_3;

                fixed (ulong* hash = &Hash[0])
                fixed (ulong* iv = &Blake2Constants.IV[0])
                {
                    v_0 = Avx2.LoadVector256(hash);
                    v_1 = Avx2.LoadVector256(hash + 4);
                    v_2 = Avx2.LoadVector256(iv);
                    v_3 = Avx2.LoadVector256(iv + 4);

                    var r_14 = isFinal ? ulong.MaxValue : 0;
                    var t_0 = Vector256.Create(TotalSegmentsLow, TotalSegmentsHigh, r_14, 0);
                    v_3 = Avx2.Xor(v_3, t_0);
                }

                fixed (byte* dataBuffer = &DataBuffer[0])
                {
                    ulong* buffer = (ulong*)dataBuffer;
                    for (var i = 0; i < 16; i++)
                    {
                        m[i] = buffer[i];
                    }

                    // this is necessary for proper function
                    // but definitely not ideal
                    if (!BitConverter.IsLittleEndian)
                    {
                        for (var i = 0; i < 16; i++)
                        {
                            m[i] = (m[i] >> 56) ^
                                ((m[i] >> 40) & 0xff00UL) ^
                                ((m[i] >> 24) & 0xff0000UL) ^
                                ((m[i] >> 8) & 0xff000000UL) ^
                                ((m[i] << 8) & 0xff00000000UL) ^
                                ((m[i] << 24) & 0xff0000000000UL) ^
                                ((m[i] << 40) & 0xff000000000000UL) ^
                                ((m[i] << 56) & 0xff00000000000000UL);
                        }
                    }
                }

                Vector256<ulong> orig_0 = v_0;
                Vector256<ulong> orig_1 = v_1;
                Vector256<ulong> orig_2 = v_2;
                Vector256<ulong> orig_3 = v_3;

                for (var i = 0; i < 12; ++i)
                {
                    Vector256<ulong> x_0;
                    Vector256<ulong> x_1;
                    Vector256<ulong> y_0;
                    Vector256<ulong> y_1;
                    fixed (int* sig = &Blake2Constants.Sigma[i][0])
                    {
                        x_0= Vector256.Create(m[sig[0]], m[sig[2]], m[sig[4]], m[sig[6]]);
                        y_0= Vector256.Create(m[sig[1]], m[sig[3]], m[sig[5]], m[sig[7]]);

                        x_1= Vector256.Create(m[sig[8]], m[sig[10]], m[sig[12]], m[sig[14]]);
                        y_1= Vector256.Create(m[sig[9]], m[sig[11]], m[sig[13]], m[sig[15]]);
                    }

                    Mix(r24, r16, ref v_0, ref v_1, ref v_2, ref v_3, x_0, y_0);

                    v_1 = Avx2.Permute4x64(v_1, 0b_00_11_10_01);
                    v_2 = Avx2.Permute4x64(v_2, 0b_01_00_11_10);
                    v_3 = Avx2.Permute4x64(v_3, 0b_10_01_00_11);

                    Mix(r24, r16, ref v_0, ref v_1, ref v_2, ref v_3, x_1, y_1);

                    v_1 = Avx2.Permute4x64(v_1, 0b_10_01_00_11);
                    v_2 = Avx2.Permute4x64(v_2, 0b_01_00_11_10);
                    v_3 = Avx2.Permute4x64(v_3, 0b_00_11_10_01);
                }

                v_0 = Avx2.Xor(v_0, orig_0);
                v_0 = Avx2.Xor(v_0, v_2);
                v_1 = Avx2.Xor(v_1, orig_1);
                v_1 = Avx2.Xor(v_1, v_3);

                fixed (ulong* hash = &Hash[0])
                {
                    Avx.Store(hash, v_0);
                    Avx.Store(hash + 4, v_1);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void Mix(Vector256<byte> r24, Vector256<byte> r16, ref Vector256<ulong> v_0, ref Vector256<ulong> v_1, ref Vector256<ulong> v_2, ref Vector256<ulong> v_3, Vector256<ulong> x, Vector256<ulong> y)
        {
            unchecked
            {
                v_0 = Avx2.Add(Avx2.Add(v_0, v_1), x);
                v_3 = Avx2.Shuffle(Avx2.Xor(v_3, v_0).AsUInt32(), 0b_10_11_00_01).AsUInt64();

                v_2 = Avx2.Add(v_2, v_3);
                v_1 = Avx2.Shuffle(Avx2.Xor(v_1, v_2).AsByte(), r24).AsUInt64();

                v_0 = Avx2.Add(Avx2.Add(v_0, v_1), y);
                v_3 = Avx2.Shuffle(Avx2.Xor(v_3, v_0).AsByte(), r16).AsUInt64();

                v_2 = Avx2.Add(v_2, v_3);
                v_1 = Avx2.Xor(v_1, v_2);
                v_1 = Avx2.Or(Avx2.ShiftLeftLogical(v_1, 1), Avx2.ShiftRightLogical(v_1, 63));
            }
        }
    }
}
#endif