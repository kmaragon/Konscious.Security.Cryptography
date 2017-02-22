namespace Konscious.Security.Cryptography
{
    using System;

    internal abstract class Blake2bBase
    {
        public Blake2bBase(int hashBytes)
        {
            _hashSize = (uint)hashBytes;
        }

        public int ByteSize
        {
            get
            {
                return (int)_hashSize;
            }
        }

        public void Initialize(byte[] key)
        {
            Array.Copy(Blake2Constants.IV, _h, 8);
            _h[0] ^= 0x01010000UL ^ (((ulong)(key?.Length ?? 0)) << 8) ^ _hashSize;

            // start with the key
            if (key?.Length > 0)
            {
                Array.Copy(key, _b, key.Length);
                Update(_b, 0, _b.Length);
            }
        }

        public void Update(byte[] data, int offset, int size)
        {
            while (size > 0)
            {
                int nextChunk = Math.Min(size, 128 - _c);

                // copy the next batch of data
                Array.Copy(data, offset, _b, _c, nextChunk);
                _c += nextChunk;
                offset += nextChunk;

                if (_c == 128)
                {
                    _t[0] += (ulong)_c;
                    if (_t[0] < (ulong)_c)
                        ++_t[1];

                    // we filled our buffer
                    this.Compress(false);
                    _c = 0;
                }

                size -= nextChunk;
            }
        }

        public byte[] Final()
        {
            _t[0] += (ulong)_c;
            if (_t[0] < (ulong)_c)
                ++_t[1];

            while (_c < 128)
                _b[_c++] = 0;
            _c = 0;

            this.Compress(true);
            var hashByteSize = _hashSize;
            byte[] result = new byte[hashByteSize];
            for (var i = 0; i < hashByteSize; ++i)
            {
                result[i] = (byte)((_h[i >> 3] >> (8 * (i & 7))) & 0xff);
            }

            return result;
        }

        public abstract void Compress(bool isFinal);

        protected ulong[] Hash
        {
            get
            {
                return _h;
            }
        }

        protected ulong TotalSegmentsLow
        {
            get
            {
                return _t[0];
            }
        }

        protected ulong TotalSegmentsHigh
        {
            get
            {
                return _t[1];
            }
        }

        protected byte[] DataBuffer
        {
            get
            {
                return _b;
            }
        }

        private ulong[] _h = new ulong[8];
        private ulong[] _t = new ulong[2];
        private byte[] _b = new byte[128];
        private int   _c;
        private uint   _hashSize;
    }
}