namespace Konscious.Security.Cryptography
{
    /// <summary>
    /// The default <see cref="IArgon2MemoryAllocator"/>: it allocates a fresh (zeroed) array for each rent and
    /// lets the garbage collector reclaim it on return. This preserves Argon2's original allocation behavior and
    /// is used unless the caller opts in to a custom (e.g. pooling) allocator via <see cref="Argon2.MemoryAllocator"/>.
    /// </summary>
    public sealed class DefaultArgon2MemoryAllocator : IArgon2MemoryAllocator
    {
        /// <summary>
        /// A shared instance of the default allocator.
        /// </summary>
        public static readonly DefaultArgon2MemoryAllocator Instance = new DefaultArgon2MemoryAllocator();

        /// <inheritdoc />
        public ulong[] Rent(int minimumLength)
        {
            // A freshly allocated array is already zeroed, satisfying the Rent contract.
            return new ulong[minimumLength];
        }

        /// <inheritdoc />
        public void Return(ulong[] buffer)
        {
            // Nothing to do; the garbage collector reclaims the array.
        }
    }
}
