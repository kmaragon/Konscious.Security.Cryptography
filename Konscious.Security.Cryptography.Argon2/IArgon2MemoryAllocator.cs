using System.Diagnostics.CodeAnalysis;

namespace Konscious.Security.Cryptography
{
    /// <summary>
    /// Supplies the large working buffers Argon2 needs while hashing. By default Argon2 allocates a fresh array
    /// per hash; for server workloads with high memory-cost parameters those arrays land on the Large Object Heap
    /// and put heavy pressure on the garbage collector. Implementing this interface lets a caller pool and reuse
    /// the buffers instead (e.g. a bounded pool, or <c>ArrayPool</c>), following the same Rent/Return shape.
    /// See https://github.com/kmaragon/Konscious.Security.Cryptography/issues/35.
    /// </summary>
    /// <remarks>
    /// Implementations must be safe for concurrent use. A single allocator is typically shared across many hashes
    /// running in parallel, and Argon2 calls <see cref="Rent"/> once per lane and <see cref="Return"/> from a
    /// <c>finally</c> without synchronizing itself, so an unsynchronized pool could hand the same buffer to two
    /// lanes and corrupt the output.
    /// </remarks>
    public interface IArgon2MemoryAllocator
    {
        /// <summary>
        /// Rent a <see cref="ulong"/> buffer of at least <paramref name="minimumLength"/> elements. The returned
        /// buffer may be larger; Argon2 uses only the first <paramref name="minimumLength"/> elements.
        /// </summary>
        /// <remarks>
        /// The returned memory MUST be zeroed. Argon2's first pass XORs into each block (<c>dest ^= ...</c>), so a
        /// non-zeroed buffer would corrupt the hash. Buffers are cleared before being handed to <see cref="Return"/>,
        /// so a pool may recycle a returned buffer as-is; the default allocator returns a fresh (already zeroed) array.
        /// </remarks>
        /// <param name="minimumLength">The minimum number of <see cref="ulong"/> elements required.</param>
        ulong[] Rent(int minimumLength);

        /// <summary>
        /// Return a buffer previously obtained from <see cref="Rent"/>. After returning, the caller must not use
        /// the buffer again.
        /// </summary>
        /// <param name="buffer">The buffer to return.</param>
        [SuppressMessage("Microsoft.Naming", "CA1716", Justification = "Rent/Return intentionally mirrors System.Buffers.ArrayPool<T>, the established pooling API shape.")]
        void Return(ulong[] buffer);
    }
}
