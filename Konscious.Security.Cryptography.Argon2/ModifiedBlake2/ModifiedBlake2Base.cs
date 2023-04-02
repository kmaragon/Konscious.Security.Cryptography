using System;

namespace Konscious.Security.Cryptography;

internal abstract class ModifiedBlake2Base : IModifiedBlake2
{
    public void Blake2Prime(Memory<ulong> memory, LittleEndianActiveStream dataStream, int size = -1)
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
    
    public abstract void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refb, ReadOnlySpan<ulong> prev);
    
    public abstract bool IsSupported { get; }
}