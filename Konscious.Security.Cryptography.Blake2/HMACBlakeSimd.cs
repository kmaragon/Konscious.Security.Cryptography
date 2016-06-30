using System.Diagnostics;

namespace Konscious.Security.Cryptography
{
    internal static class HMACBlakeSimd
    {
        public static unsafe void Compress(byte[] data, ulong[] hash, ulong[] totalSize, bool isFinal)
        {
            Debug.Assert(data.Length == 128);
            Debug.Assert(hash.Length == 8);
            Debug.Assert(totalSize.Length == 2);

            unchecked
            {
                ulong *v = stackalloc ulong[16];
                ulong *m = stackalloc ulong[16];

                for (var i = 0; i < 8; ++i)
                    v[i] = hash[i];
                for (var i = 0; i < 8; ++i)
                    v[i + 8] = Blake2Constants.IV[i];

                v[12] ^= totalSize[0];
                v[13] ^= totalSize[1];

                if (isFinal)
                    v[14] = ~v[14];

                for (var i = 0; i < 16; ++i)
                {
                    int dataOffset = 8 * i;

                    m[i] = ((ulong)data[dataOffset]) ^
                        (((ulong)data[dataOffset + 1]) << 8) ^
                        (((ulong)data[dataOffset + 2]) << 16) ^
                        (((ulong)data[dataOffset + 3]) << 24) ^
                        (((ulong)data[dataOffset + 4]) << 32) ^
                        (((ulong)data[dataOffset + 5]) << 40) ^
                        (((ulong)data[dataOffset + 6]) << 48) ^
                        (((ulong)data[dataOffset + 7]) << 56);
                }

                for (var i = 0; i < 12; ++i)
                {
                    v[0] = v[0] + v[4] + m[Blake2Constants.Sigma[i][0]];
                    v[12] = ((v[12] ^ v[0]) >> 16) ^ ((v[12] ^ v[0]) << 16);
                    v[8] = v[8] + v[12];
                    v[4] = ((v[4] ^ v[8]) >> 12) ^ ((v[4] ^ v[8]) << 20);
                    v[0] = v[0] + v[4] + m[Blake2Constants.Sigma[i][1]];
                    v[12] = ((v[12] ^ v[0]) >> 8) ^ ((v[12] ^ v[0]) << 24);
                    v[8] = v[8] + v[12];
                    v[4] = ((v[4] ^ v[8]) >> 7) ^ ((v[4] ^ v[8]) << 25);

                    v[1] = v[1] + v[5] + m[Blake2Constants.Sigma[i][2]];
                    v[13] = ((v[13] ^ v[1]) >> 16) ^ ((v[13] ^ v[1]) << 16);
                    v[9] = v[9] + v[13];
                    v[5] = ((v[5] ^ v[9]) >> 12) ^ ((v[5] ^ v[9]) << 20);
                    v[1] = v[1] + v[5] + m[Blake2Constants.Sigma[i][3]];
                    v[13] = ((v[13] ^ v[1]) >> 8) ^ ((v[13] ^ v[1]) << 24);
                    v[9] = v[9] + v[13];
                    v[5] = ((v[5] ^ v[9]) >> 7) ^ ((v[5] ^ v[9]) << 25);
                }

                for (var i = 0; i < 8; ++i)
                    hash[i] ^= v[i] ^ v[i + 8];
            }
        }
    }
}