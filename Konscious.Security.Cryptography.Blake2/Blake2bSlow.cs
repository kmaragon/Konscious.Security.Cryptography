using System.Diagnostics;

namespace Konscious.Security.Cryptography
{
    internal class Blake2bSlow : Blake2bBase
    {
        public Blake2bSlow(int hashBytes)
            : base(hashBytes)
        {
        }

        public override void Compress(bool isFinal)
        {
            Debug.Assert(DataBuffer.Length == 128);
            Debug.Assert(Hash.Length == 8);

            ulong[] v = new ulong[16];
            ulong[] m = new ulong[16];

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
                DoRoundSlow(v, m, i);
            }

            for (var i = 0; i < 8; ++i)
                Hash[i] ^= v[i] ^ v[i + 8];
        }

        private static ulong RotateSlow(ulong x, int y)
        {
            return (((x) >> (y)) ^ ((x) << (64 - (y))));
        }

        private static void SlowG(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = RotateSlow(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = RotateSlow(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = RotateSlow(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = RotateSlow(v[b] ^ v[c], 63);
        }

        private static void DoRoundSlow(ulong[] v, ulong[] m, int i)
        {
           SlowG(v, 0, 4,  8, 12, m[Blake2Constants.Sigma[i][ 0]], m[Blake2Constants.Sigma[i][ 1]]);
           SlowG(v, 1, 5,  9, 13, m[Blake2Constants.Sigma[i][ 2]], m[Blake2Constants.Sigma[i][ 3]]);
           SlowG(v, 2, 6, 10, 14, m[Blake2Constants.Sigma[i][ 4]], m[Blake2Constants.Sigma[i][ 5]]);
           SlowG(v, 3, 7, 11, 15, m[Blake2Constants.Sigma[i][ 6]], m[Blake2Constants.Sigma[i][ 7]]);
           SlowG(v, 0, 5, 10, 15, m[Blake2Constants.Sigma[i][ 8]], m[Blake2Constants.Sigma[i][ 9]]);
           SlowG(v, 1, 6, 11, 12, m[Blake2Constants.Sigma[i][10]], m[Blake2Constants.Sigma[i][11]]);
           SlowG(v, 2, 7,  8, 13, m[Blake2Constants.Sigma[i][12]], m[Blake2Constants.Sigma[i][13]]);
           SlowG(v, 3, 4,  9, 14, m[Blake2Constants.Sigma[i][14]], m[Blake2Constants.Sigma[i][15]]);
        }
    }
}