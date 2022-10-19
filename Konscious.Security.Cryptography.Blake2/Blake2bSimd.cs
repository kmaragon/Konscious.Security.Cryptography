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
            Span<ulong> v = stackalloc ulong[16];
            Span<ulong> m = stackalloc ulong[16];

            for (var i = 0; i < 8; ++i)
                v[i] = Hash[i];
            for (var i = 0; i < 8; ++i)
                v[i + 8] = Blake2Constants.IV[i];

            v[12] ^= TotalSegmentsLow;
            v[13] ^= TotalSegmentsHigh;

            if (isFinal)
                v[14] = ~v[14];

            for (var i = 0; i < 16; ++i)
            {
                int DataBufferOffset = 8 * i;

                m[i] = ((ulong)DataBuffer[DataBufferOffset]) ^
                    (((ulong)DataBuffer[DataBufferOffset + 1]) << 8) ^
                    (((ulong)DataBuffer[DataBufferOffset + 2]) << 16) ^
                    (((ulong)DataBuffer[DataBufferOffset + 3]) << 24) ^
                    (((ulong)DataBuffer[DataBufferOffset + 4]) << 32) ^
                    (((ulong)DataBuffer[DataBufferOffset + 5]) << 40) ^
                    (((ulong)DataBuffer[DataBufferOffset + 6]) << 48) ^
                    (((ulong)DataBuffer[DataBufferOffset + 7]) << 56);
            }

            for (var i = 0; i < 12; ++i)
            {
                v[0] = v[0] + v[4] + m[Blake2Constants.Sigma[i][0]];
                var temp = v[12] ^ v[0];
                v[12] = (temp >> 32) ^ (temp << 32);
                v[8] = v[8] + v[12];
                temp = v[4] ^ v[8];
                v[4] = (temp >> 24) ^ (temp << 40);
                v[0] = v[0] + v[4] + m[Blake2Constants.Sigma[i][1]];
                temp = v[12] ^ v[0];
                v[12] = (temp >> 16) ^ (temp << 48);
                v[8] = v[8] + v[12];
                temp = v[4] ^ v[8];
                v[4] = (temp >> 63) ^ (temp << 1);

                v[1] = v[1] + v[5] + m[Blake2Constants.Sigma[i][2]];
                temp = v[13] ^ v[1];
                v[13] = (temp >> 32) ^ (temp << 32);
                v[9] = v[9] + v[13];
                temp = v[5] ^ v[9];
                v[5] = (temp >> 24) ^ (temp << 40);
                v[1] = v[1] + v[5] + m[Blake2Constants.Sigma[i][3]];
                temp = v[13] ^ v[1];
                v[13] = (temp >> 16) ^ (temp << 48);
                v[9] = v[9] + v[13];
                temp = v[5] ^ v[9];
                v[5] = (temp >> 63) ^ (temp << 1);

                v[2] = v[2] + v[6] + m[Blake2Constants.Sigma[i][4]];
                temp = v[14] ^ v[2];
                v[14] = (temp >> 32) ^ (temp << 32);
                v[10] = v[10] + v[14];
                temp = v[6] ^ v[10];
                v[6] = (temp >> 24) ^ (temp << 40);
                v[2] = v[2] + v[6] + m[Blake2Constants.Sigma[i][5]];
                temp = v[14] ^ v[2];
                v[14] = (temp >> 16) ^ (temp << 48);
                v[10] = v[10] + v[14];
                temp = v[6] ^ v[10];
                v[6] = (temp >> 63) ^ (temp << 1);

                v[3] = v[3] + v[7] + m[Blake2Constants.Sigma[i][6]];
                temp = v[15] ^ v[3];
                v[15] = (temp >> 32) ^ (temp << 32);
                v[11] = v[11] + v[15];
                temp = v[7] ^ v[11];
                v[7] = (temp >> 24) ^ (temp << 40);
                v[3] = v[3] + v[7] + m[Blake2Constants.Sigma[i][7]];
                temp = v[15] ^ v[3];
                v[15] = (temp >> 16) ^ (temp << 48);
                v[11] = v[11] + v[15];
                temp = v[7] ^ v[11];
                v[7] = (temp >> 63) ^ (temp << 1);

                v[0] = v[0] + v[5] + m[Blake2Constants.Sigma[i][8]];
                temp = v[15] ^ v[0];
                v[15] = (temp >> 32) ^ (temp << 32);
                v[10] = v[10] + v[15];
                temp = v[5] ^ v[10];
                v[5] = (temp >> 24) ^ (temp << 40);
                v[0] = v[0] + v[5] + m[Blake2Constants.Sigma[i][9]];
                temp = v[15] ^ v[0];
                v[15] = (temp >> 16) ^ (temp << 48);
                v[10] = v[10] + v[15];
                temp = v[5] ^ v[10];
                v[5] = (temp >> 63) ^ (temp << 1);

                v[1] = v[1] + v[6] + m[Blake2Constants.Sigma[i][10]];
                temp = v[12] ^ v[1];
                v[12] = (temp >> 32) ^ (temp << 32);
                v[11] = v[11] + v[12];
                temp = v[6] ^ v[11];
                v[6] = (temp >> 24) ^ (temp << 40);
                v[1] = v[1] + v[6] + m[Blake2Constants.Sigma[i][11]];
                temp = v[12] ^ v[1];
                v[12] = (temp >> 16) ^ (temp << 48);
                v[11] = v[11] + v[12];
                temp = v[6] ^ v[11];
                v[6] = (temp >> 63) ^ (temp << 1);

                v[2] = v[2] + v[7] + m[Blake2Constants.Sigma[i][12]];
                temp = v[13] ^ v[2];
                v[13] = (temp >> 32) ^ (temp << 32);
                v[8] = v[8] + v[13];
                temp = v[7] ^ v[8];
                v[7] = (temp >> 24) ^ (temp << 40);
                v[2] = v[2] + v[7] + m[Blake2Constants.Sigma[i][13]];
                temp = v[13] ^ v[2];
                v[13] = (temp >> 16) ^ (temp << 48);
                v[8] = v[8] + v[13];
                temp = v[7] ^ v[8];
                v[7] = (temp >> 63) ^ (temp << 1);

                v[3] = v[3] + v[4] + m[Blake2Constants.Sigma[i][14]];
                temp = v[14] ^ v[3];
                v[14] = (temp >> 32) ^ (temp << 32);
                v[9] = v[9] + v[14];
                temp = v[4] ^ v[9];
                v[4] = (temp >> 24) ^ (temp << 40);
                v[3] = v[3] + v[4] + m[Blake2Constants.Sigma[i][15]];
                temp = v[14] ^ v[3];
                v[14] = (temp >> 16) ^ (temp << 48);
                v[9] = v[9] + v[14];
                temp = v[4] ^ v[9];
                v[4] = (temp >> 63) ^ (temp << 1);
            }

            for (var i = 0; i < 8; ++i)
                Hash[i] ^= v[i] ^ v[i + 8];
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