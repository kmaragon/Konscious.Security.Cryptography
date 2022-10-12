#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace Konscious.Security.Cryptography
{
    internal static class ModifiedBlake2Intrinsics
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

        private static ReadOnlySpan<byte> rormask => new byte[] {
            3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, //r24
			2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9  //r16
		};

        public static unsafe void DoRoundColumns(ulong* v, int i)
        {
            i *= 16;

            byte* prm = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(rormask));
            var r24 = Avx2.BroadcastVector128ToVector256(prm);
            var r16 = Avx2.BroadcastVector128ToVector256(prm + Vector128<byte>.Count);

            var mask = Vector256.CreateScalar((ulong)uint.MaxValue);
            var row1 = Avx2.LoadVector256(v+i);
            var row2 = Avx2.LoadVector256(v+i + Vector256<ulong>.Count);
            var row3 = Avx2.LoadVector256(v+i+ (Vector256<ulong>.Count * 2));
            var row4 = Avx2.LoadVector256(v+i + (Vector256<ulong>.Count * 3));

            // G1
            var t = Avx2.Multiply(row1.AsUInt32(), row2.AsUInt32());
            row1 = Avx2.Add(Avx2.Add(row1, row2), Avx2.Add(t, t));
            row4 = Avx2.Xor(row4, row1);
            row4 = Avx2.Shuffle(row4.AsUInt32(), 0b_10_11_00_01).AsUInt64();

            t = Avx2.Multiply(row3.AsUInt32(), row4.AsUInt32());
            row3 = Avx2.Add(Avx2.Add(row3, row4), Avx2.Add(t, t));
            row2 = Avx2.Xor(row2, row3);
            row2 = Avx2.Shuffle(row2.AsByte(), r24).AsUInt64();

            // G2
            t = Avx2.Multiply(row1.AsUInt32(), row2.AsUInt32());
            row1 = Avx2.Add(Avx2.Add(row1, row2), Avx2.Add(t, t));
            row4 = Avx2.Xor(row4, row1);
            row4 = Avx2.Shuffle(row4.AsByte(), r16).AsUInt64();

            t = Avx2.Multiply(row3.AsUInt32(), row4.AsUInt32());
            row3 = Avx2.Add(Avx2.Add(row3, row4), Avx2.Add(t, t));
            row2 = Avx2.Xor(row2, row3);
            // Double check might be related to the diagonisation.
            row2 = Avx2.Xor(Avx2.ShiftRightLogical(row2, 63), Avx2.Add(row2, row2));

            // DIAGONALIZE
            row1 = Avx2.Permute4x64(row1, 0b_10_01_00_11);
            row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
            row3 = Avx2.Permute4x64(row3, 0b_00_11_10_01);

            // G1
            t = Avx2.Multiply(row1.AsUInt32(), row2.AsUInt32());
            row1 = Avx2.Add(Avx2.Add(row1, row2), Avx2.Add(t, t));
            row4 = Avx2.Xor(row4, row1);
            row4 = Avx2.Shuffle(row4.AsUInt32(), 0b_10_11_00_01).AsUInt64();

            t = Avx2.Multiply(row3.AsUInt32(), row4.AsUInt32());
            row3 = Avx2.Add(Avx2.Add(row3, row4), Avx2.Add(t, t));
            row2 = Avx2.Xor(row2, row3);
            row2 = Avx2.Shuffle(row2.AsByte(), r24).AsUInt64();

            // G2
            t = Avx2.Multiply(row1.AsUInt32(), row2.AsUInt32());
            row1 = Avx2.Add(Avx2.Add(row1, row2), Avx2.Add(t, t));
            row4 = Avx2.Xor(row4, row1);
            row4 = Avx2.Shuffle(row4.AsByte(), r16).AsUInt64();

            t = Avx2.Multiply(row3.AsUInt32(), row4.AsUInt32());
            row3 = Avx2.Add(Avx2.Add(row3, row4), Avx2.Add(t, t));
            row2 = Avx2.Xor(row2, row3);
            // Double check might be related to the diagonisation.
            row2 = Avx2.Xor(Avx2.ShiftRightLogical(row2, 63), Avx2.Add(row2, row2));

            // UNDIAGONALIZE
            row1 = Avx2.Permute4x64(row1, 0b_00_11_10_01);
            row4 = Avx2.Permute4x64(row4, 0b_01_00_11_10);
            row3 = Avx2.Permute4x64(row3, 0b_10_01_00_11);

            Avx.Store(v + i, row1);
            Avx.Store(v + i + Vector256<ulong>.Count, row2);
            Avx.Store(v + i + Vector256<ulong>.Count * 2, row3);
            Avx.Store(v + i + Vector256<ulong>.Count * 3, row4);

            //ModifiedG(v, i, i + 4, i + 8, i + 12);
            //ModifiedG(v, i + 1, i + 5, i + 9, i + 13);
            //ModifiedG(v, i + 2, i + 6, i + 10, i + 14);
            //ModifiedG(v, i + 3, i + 7, i + 11, i + 15);

            //ModifiedG(v, i, i + 5, i + 10, i + 15);
            //ModifiedG(v, i + 1, i + 6, i + 11, i + 12);
            //ModifiedG(v, i + 2, i + 7, i + 8, i + 13);
            //ModifiedG(v, i + 3, i + 4, i + 9, i + 14);
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
                memory.Span.Blit(blake2.ComputeHash(hashStream).AsSpan().Slice(0,size), 0);
            }
            else
            {
                var blake2 = new HMACBlake2B(512);
                blake2.Initialize();

                int offset = 0;
                var chunk = blake2.ComputeHash(hashStream);

                memory.Span.Blit(chunk.AsSpan().Slice(0,32), offset); // copy half of the chunk
                offset += 4;
                size -= 32;

                while (size > 64)
                {
                    blake2.Initialize();
                    chunk = blake2.ComputeHash(chunk);
                    memory.Span.Blit(chunk.AsSpan().Slice(0,32), offset); // half again

                    offset += 4;
                    size -= 32;
                }

                blake2 = new HMACBlake2B(size * 8);
                blake2.Initialize();
                memory.Span.Blit(blake2.ComputeHash(chunk).AsSpan().Slice(0,size), offset); // copy the rest
            }
        }
    }
}
#endif
