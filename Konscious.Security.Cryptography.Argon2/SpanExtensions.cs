namespace Konscious.Security.Cryptography
{
    using System;
    using System.Runtime.InteropServices;

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
                remainder = byteLength % 8;
            }

            var newSpan = MemoryMarshal.Cast<byte, ulong>(bytes[srcOffset..]);
            newSpan.CopyTo(toBlit[destOffset..]);

            if (remainder != 0)
            {
                var remainderSpan = bytes[^remainder..];

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