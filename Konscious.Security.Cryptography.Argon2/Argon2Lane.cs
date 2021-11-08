namespace Konscious.Security.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

    internal class Argon2Lane
    {
        public Argon2Lane(int blockCount)
        {
            _memory = new Memory<ulong>(new ulong[128 * blockCount]);
            BlockCount = blockCount;
        }

        public Argon2Memory this[int index]
        {
            get
            {
                if (index < 0 || index > BlockCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                return new Argon2Memory(_memory.Slice(128*index, 128));
            }
        }

        public int BlockCount { get; }

        private readonly Memory<ulong> _memory;
    }

    internal static class SpanExtensions
    {
        public static void Blit(this Span<ulong> toBlit, ReadOnlySpan<byte> bytes, int destOffset = 0, int srcOffset = 0, int byteLength = -1)
        {
            int remainder = 0;
            int length;
            if (byteLength < 0)
            {
                length = 128;
            }
            else
            {
                length = byteLength / 8;
                remainder = byteLength - (length * 8);
            }
            //---------------
            var newSpan = MemoryMarshal.Cast<byte, ulong>(bytes[srcOffset..]);
            newSpan.CopyTo(toBlit[destOffset..]);

            if (remainder != 0)
            {
                var remainderSpan = bytes[^(byteLength % 8)..];

                ulong extra = 0;
                for (int i = 0; i < remainderSpan.Length; i++)
                {
                    extra |= ((ulong)remainderSpan[i]) << (8 * i);
                }
                toBlit[newSpan.Length + destOffset] = extra;
            }
        }
    }
}