namespace Konscious.Security.Cryptography
{
    using System;

    internal class Argon2Lane : IDisposable
    {
        public Argon2Lane(int blockCount, IArgon2MemoryAllocator allocator)
        {
            _allocator = allocator;
            var length = 128 * blockCount;

            // The allocator contract requires Rent to return zeroed memory: Argon2's first pass XORs into each
            // block (dest ^= ...), so a non-zeroed starting buffer would corrupt the hash. The default allocator
            // hands back a fresh (zeroed) array, and Dispose zeroes reused buffers before returning them, so a
            // pooling allocator can recycle the same memory without clearing it itself.
            _rented = allocator.Rent(length);
            _memory = new Memory<ulong>(_rented, 0, length);
            BlockCount = blockCount;
        }

        public Memory<ulong> this[int index]
        {
            get
            {
                if (index < 0 || index > BlockCount)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                return _memory.Slice(128*index, 128);
            }
        }

        public int BlockCount { get; }

        public void Dispose()
        {
            var rented = _rented;
            if (rented != null)
            {
                _rented = null;

                // Clear the working memory before handing it back. It holds password-derived state, so zeroing
                // wipes that material promptly, and it lets any allocator (including a pool) satisfy the
                // "Rent returns zeroed" contract without clearing again.
                Array.Clear(rented, 0, 128 * BlockCount);
                _allocator.Return(rented);
            }
        }

        private readonly IArgon2MemoryAllocator _allocator;
        private ulong[] _rented;
        private readonly Memory<ulong> _memory;
    }
}
