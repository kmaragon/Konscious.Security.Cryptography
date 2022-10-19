namespace Konscious.Security.Cryptography
{
    internal class Blake2bNormal : Blake2bBase
    {
        public Blake2bNormal(int hashBytes)
            : base(hashBytes)
        {
        }

        public override void Compress(bool isFinal)
        {
            unsafe
            {
                ulong* v = stackalloc ulong[16];
                ulong* m = stackalloc ulong[16];

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
        }
    }
}