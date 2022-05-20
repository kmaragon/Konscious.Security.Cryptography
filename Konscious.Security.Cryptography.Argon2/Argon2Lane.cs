namespace Konscious.Security.Cryptography
{
    using System;

    internal class Argon2Lane
    {
        public Argon2Lane(int blockCount)
        {
            _memory = new Memory<ulong>(new ulong[128 * blockCount]);
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

        private readonly Memory<ulong> _memory;
    }
}