namespace Konscious.Security.Cryptography
{
    using System;

    internal class Argon2Lane
    {
        public Argon2Lane(int blockCount)
        {
            _memory = new ulong[128 * blockCount];
        }

        public Argon2Memory this[int index]
        {
            get
            {
                if (index < 0 || index > BlockCount)
                {
                    throw new ArgumentOutOfRangeException();
                }

                return new Argon2Memory(_memory, 128 * index);
            }
        }

        public int BlockCount
        {
            get
            {
                return _memory.Length / 128;
            }
        }

        private ulong[] _memory;
    }
}