namespace Konscious.Security.Cryptography
{
    using System;

    internal class Blake2bSimd : Blake2bBase
    {
        public Blake2bSimd(int HashBytes)
            : base(HashBytes)
        {
        }

        public unsafe override void Compress(bool isFinal)
        {
            unchecked
            {
                ulong* v = stackalloc ulong[16];
                ulong* m = stackalloc ulong[16];

                fixed (ulong *hash = &Hash[0])
                {
                    for (var i = 0; i < 8; i++)
                        v[i] = hash[i];
                }

                fixed (ulong *iv = &Blake2Constants.IV[0])
                {
                    for (var i = 0; i < 8; i++)
                        v[i + 8] = Blake2Constants.IV[i];
                }

                v[12] ^= TotalSegmentsLow;
                v[13] ^= TotalSegmentsHigh;

                if (isFinal)
                    v[14] = ~v[14];

                fixed (byte *dataBuffer = &DataBuffer[0])
                {
                    ulong *buffer = (ulong*)dataBuffer;
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

                for (var i = 0; i < 12; ++i)
                {
#pragma warning disable CA2014 // Do not use stackalloc in loops
                    ulong* sigmaodd = stackalloc ulong[4];
#pragma warning restore CA2014 // Do not use stackalloc in loops
                    sigmaodd[0] =  m[Blake2Constants.Sigma[i][0]];
                    sigmaodd[1] = m[Blake2Constants.Sigma[i][2]];
                    sigmaodd[2] = m[Blake2Constants.Sigma[i][4]];
                    sigmaodd[3] = m[Blake2Constants.Sigma[i][6]];

                    ulong *u = &v[4];
                    // these guys should get JIT optimized into SIMD instructions
                    for (var x = 0; x < 4; x++)
                        v[x] += u[x];
                    for (var x = 0; x < 4; x++)
                        v[x] += sigmaodd[x];

                    // TODO keep optimizing
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

                    sigmaodd[0] = m[Blake2Constants.Sigma[i][8]];
                    sigmaodd[1] = m[Blake2Constants.Sigma[i][10]];
                    sigmaodd[2] = m[Blake2Constants.Sigma[i][12]];

                    // "
                    u = &v[5];
                    for (var x = 0; x < 3; x++)
                        v[x] += u[x];
                    for (var x = 0; x < 3; x++)
                        v[x] += sigmaodd[x];

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
        }
    }
}