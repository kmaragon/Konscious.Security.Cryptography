using System;

namespace Konscious.Security.Cryptography;

internal interface IModifiedBlake2
{
    void Blake2Prime(Memory<ulong> memory, LittleEndianActiveStream dataStream, int size = -1);
    
    void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refb, ReadOnlySpan<ulong> prev);
    
    bool IsSupported { get; }
}