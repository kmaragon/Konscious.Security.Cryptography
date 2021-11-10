using System;

namespace Konscious.Security.Cryptography
{
    internal static class ModifiedBlake2
    {

        private static ulong Rotate(ulong x, int y)
        {
            return (((x) >> (y)) ^ ((x) << (64 - (y))));
        }

        private unsafe static void ModifiedG(ulong *v, int a, int b, int c, int d)
        {
            var t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
            v[a] = v[a] + v[b] + 2 * t;

            v[d] = Rotate(v[d] ^ v[a], 32);

            t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
            v[c] = v[c] + v[d] + 2 * t;

            v[b] = Rotate(v[b] ^ v[c], 24);

            t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
            v[a] = v[a] + v[b] + 2 * t;


            v[d] = Rotate(v[d] ^ v[a], 16);

            t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
            v[c] = v[c] + v[d] + 2 * t;

            v[b] = Rotate(v[b] ^ v[c], 63);
        }

        public unsafe static void DoRoundColumns(ulong *v, int i)
        {
            i *= 16;
            ModifiedG(v,     i, i + 4,  i + 8, i + 12);
            ModifiedG(v, i + 1, i + 5,  i + 9, i + 13);
            ModifiedG(v, i + 2, i + 6, i + 10, i + 14);
            ModifiedG(v, i + 3, i + 7, i + 11, i + 15);
            ModifiedG(v,     i, i + 5, i + 10, i + 15);
            ModifiedG(v, i + 1, i + 6, i + 11, i + 12);
            ModifiedG(v, i + 2, i + 7,  i + 8, i + 13);
            ModifiedG(v, i + 3, i + 4,  i + 9, i + 14);
        }


        public unsafe static void DoRoundRows(ulong *v, int i)
        {
            i *= 2;
            ModifiedG(v,      i, i + 32, i + 64, i +  96);
            ModifiedG(v, i +  1, i + 33, i + 65, i +  97);
            ModifiedG(v, i + 16, i + 48, i + 80, i + 112);
            ModifiedG(v, i + 17, i + 49, i + 81, i + 113);
            ModifiedG(v,      i, i + 33, i + 80, i + 113);
            ModifiedG(v, i +  1, i + 48, i + 81, i +  96);
            ModifiedG(v, i + 16, i + 49, i + 64, i +  97);
            ModifiedG(v, i + 17, i + 32, i + 65, i + 112);
        }

        public static void Blake2Prime(Memory<ulong> memory, LittleEndianActiveStream dataStream, int size = -1)
        {
            var hashStream = new LittleEndianActiveStream();

            if (size < 0 || size > (memory.Length * 8))
            {
                size = memory.Length * 8;
            }

            hashStream.Expose(size);
            hashStream.Expose(dataStream);


            if (size <= 64)
            {
                var blake2 = new HMACBlake2B(8 * size);
                blake2.Initialize();
                memory.Span.Blit(blake2.ComputeHash(hashStream).AsSpan()[0..size], 0);
            }
            else
            {
                var blake2 = new HMACBlake2B(512);
                blake2.Initialize();

                int offset = 0;
                var chunk = blake2.ComputeHash(hashStream);

                memory.Span.Blit(chunk.AsSpan()[0..32], offset); // copy half of the chunk
                offset += 4;
                size -= 32;

                while (size > 64)
                {
                    blake2.Initialize();
                    chunk = blake2.ComputeHash(chunk);
                    memory.Span.Blit(chunk.AsSpan()[0..32], offset); // half again

                    offset += 4;
                    size -= 32;
                }

                blake2 = new HMACBlake2B(size * 8);
                blake2.Initialize();
                memory.Span.Blit(blake2.ComputeHash(chunk).AsSpan()[0..size], offset); // copy the rest
            }
        }
    }
}