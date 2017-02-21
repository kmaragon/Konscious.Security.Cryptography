namespace Konscious.Security.Cryptography
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices;

    internal class Argon2Memory : IEnumerable<ulong>
    {
        private ulong[] _data;
        private int _offset;

        public Argon2Memory(ulong[] data, int offset)
        {
            _data = data;
            _offset = offset;
        }

        public int Length
        {
            get
            {
                return 128;
            }
        }

        public void Blit(byte[] data, int destOffset = 0, int srcOffset = 0, int byteLength = -1)
        {
            int remainder = 0;
            int length;
            if (byteLength < 0)
            {
                length = Length;
            }
            else
            {
                length = byteLength / 8;
                remainder = byteLength - (length * 8);
            }

            int readSize = Math.Min((data.Length / 8), length);

            var mstream = new MemoryStream(data);
            mstream.Seek(srcOffset, SeekOrigin.Begin);
            var reader = new BinaryReader(mstream);

            readSize += destOffset;
            int i = destOffset;
            for (; i < readSize; ++i)
            {
                this[i] = reader.ReadUInt64();
            }

            if (remainder > 0)
            {
                ulong extra = 0;

                // get the remainder as a few bytes
                for (var n = 0; n < remainder; ++n)
                    extra = extra | ((ulong)reader.ReadByte() << (8 * n));

                this[i++] = extra;
            }

            for (; i < length; ++i)
            {
                this[i] = 0;
            }
        }

        public void Set(ulong value)
        {
            var off = _offset;
            for (var i = 0; i < 128; i++)
            {
                _data[off++] = 0;
            }
        }

        public IEnumerator<ulong> GetEnumerator()
        {
            return new Enumerator(_data, _offset);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new Enumerator(_data, _offset);
        }

        public ulong this[int index]
        {
            get
            {
                if (index < 0 || index > 128)
                {
                    throw new ArgumentOutOfRangeException();
                }

                return _data[_offset + index];
            }
            set
            {
                if (index < 0 || index > 128)
                {
                    throw new ArgumentOutOfRangeException();
                }

                _data[_offset + index] = value;
            }
        }

        internal unsafe class Stream : UnmanagedMemoryStream
        {
            public Stream(Argon2Memory memory)
            {
                _data = GCHandle.Alloc(memory._data, GCHandleType.Pinned);
                base.Initialize((byte*)_data.AddrOfPinnedObject() + (memory._offset * 8), 1024, 1024, FileAccess.Read);
            }

            protected override void Dispose(bool isDispose)
            {
                base.Dispose(isDispose);
                _data.Free();
            }

            private GCHandle _data;
        }

        private class Enumerator : IEnumerator<ulong>
        {
            private int _start;
            private int _current;
            private ulong[] _data;

            public Enumerator(ulong[] data, int start)
            {
                _start = start;
                _data = data;

                Reset();
            }

            public ulong Current
            {
                get
                {
                    if (_current >= (_start + 128))
                        return 0UL;

                    return _data[_current];
                }
            }

            object IEnumerator.Current
            {
                get
                {
                    return (object)this.Current;
                }
            }

            public void Dispose()
            {
            }

            public bool MoveNext()
            {
                if (++_current >= (_start + 128))
                {
                    return false;
                }

                return true;
            }

            public void Reset()
            {
                _current = _start - 1;
            }
        }

    }
}