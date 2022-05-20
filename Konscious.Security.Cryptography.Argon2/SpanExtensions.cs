namespace Konscious.Security.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

    internal static class SpanExtensions
    {
        public static void Blit(this Span<ulong> toBlit, ReadOnlySpan<byte> bytes, int destOffset = 0)
        {
            if (bytes.Length/8 > toBlit.Length - destOffset)
            {
                throw new ArgumentException("Cannot write more than remaining space");
            }

            var remainder = bytes.Length % 8;
            var newSpan = MemoryMarshal.Cast<byte, ulong>(bytes);
            newSpan.CopyTo(toBlit.Slice(destOffset));

            if (remainder != 0)
            {
                var remainderSpan = bytes.Slice(bytes.Length-remainder);//CN:Here

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