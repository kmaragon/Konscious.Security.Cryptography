using System.Diagnostics.CodeAnalysis;

namespace Konscious.Security.Cryptography
{
    using System;
    using System.Buffers;
    using System.Collections;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices;

    internal class Argon2Memory
    {
        private readonly Memory<ulong> _data;

        public Argon2Memory(Memory<ulong> data)
        {
            _data = data;
        }

        public ReadOnlySpan<ulong> Span => _data.Span;

        [SuppressMessage("Microsoft.Performance", "CA1822")]
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
            //---------------
            var newSpan = MemoryMarshal.Cast<byte, ulong>(data.AsSpan(srcOffset));
            newSpan.CopyTo(_data.Span[destOffset..]);

            if (remainder != 0)
            {
                var remainderSpan = data[^(byteLength % 8)..];

                ulong extra = 0;
                for (int i = 0; i < remainderSpan.Length; i++)
                {
                    extra |= ((ulong)remainderSpan[i]) << (8 * i);
                }
                this[newSpan.Length + destOffset] = extra;
            }
            //------------
            //int readSize = Math.Min((data.Length / 8), length);

            //var mstream = new MemoryStream(data);
            //mstream.Seek(srcOffset, SeekOrigin.Begin);
            //var reader = new BinaryReader(mstream);
            //readSize += destOffset;
            //int i = destOffset;
            //for (; i < readSize; ++i)
            //{
            //    this[i] = reader.ReadUInt64();
            //}

            //if (remainder > 0)
            //{
            //    ulong extra = 0;

            //    // get the remainder as a few bytes                        
            //    for (var n = 0; n < remainder; ++n)
            //        extra = extra | ((ulong)reader.ReadByte() << (8 * n));

            //    this[i++] = extra;
            //}

            //for (; i < length; ++i)
            //{
            //    this[i] = 0;
            //}
        }

        public void Set(ulong value)
        {
            _data.Span.Fill(value);
        }

        //public IEnumerator<ulong> GetEnumerator()
        //{
            
        //    for (int i = 0; i < _data.Length; i++)
        //    {
        //        yield return _data.ToEnumerable();
        //    }
        //}

        //IEnumerator IEnumerable.GetEnumerator()
        //{
        //    return GetEnumerator();
        //}

        public ulong this[int index]
        {
            get
            {
                if (index < 0 || index > 128)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                return _data.Span[index];
            }
            set
            {
                if (index < 0 || index >= 128)
                {
                    throw new ArgumentOutOfRangeException(nameof(index));
                }

                _data.Span[index] = value;
            }
        }

        internal unsafe class Stream : UnmanagedMemoryStream
        {
            public Stream(Argon2Memory memory)
            {
                _data = memory._data.Pin();
                base.Initialize((byte*)_data.Pointer, 1024, 1024, FileAccess.Read);
                //_data = GCHandle.Alloc(memory._data, GCHandleType.Pinned);
                //base.Initialize((byte*)_data.AddrOfPinnedObject(), 1024, 1024, FileAccess.Read);
            }

            protected override void Dispose(bool isDispose)
            {
                base.Dispose(isDispose);
                _data.Dispose();
            }

            private MemoryHandle _data;
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