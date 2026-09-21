namespace Konscious.Security.Cryptography
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading.Tasks;
    using Xunit;

    public class Argon2MemoryAllocatorTests
    {
        /// <summary>
        /// A minimal pooling allocator: it reuses returned buffers, zeroes them (honoring the Rent contract),
        /// and records activity so tests can assert buffers are balanced and actually reused.
        /// </summary>
        private sealed class PoolingAllocator : IArgon2MemoryAllocator
        {
            private readonly Stack<ulong[]> _free = new Stack<ulong[]>();
            private int _outstanding;

            public int RentCount { get; private set; }
            public int ReturnCount { get; private set; }
            public int AllocationCount { get; private set; }
            public int MaxOutstanding { get; private set; }

            public ulong[] Rent(int minimumLength)
            {
                RentCount++;
                _outstanding++;
                if (_outstanding > MaxOutstanding)
                {
                    MaxOutstanding = _outstanding;
                }

                while (_free.Count > 0)
                {
                    var buf = _free.Pop();
                    if (buf.Length >= minimumLength)
                    {
                        Array.Clear(buf, 0, buf.Length); // Rent must return zeroed memory
                        return buf;
                    }
                }

                AllocationCount++;
                return new ulong[minimumLength];
            }

            public void Return(ulong[] buffer)
            {
                ReturnCount++;
                _outstanding--;
                Array.Clear(buffer, 0, buffer.Length);
                _free.Push(buffer);
            }
        }

        /// <summary>
        /// Records, per returned buffer, whether it was already all-zero when the library returned it. Used to
        /// verify that Argon2 clears working memory on dispose before handing it back to the allocator.
        /// </summary>
        private sealed class ReturnRecordingAllocator : IArgon2MemoryAllocator
        {
            public List<bool> ReturnedZeroed { get; } = new List<bool>();

            public ulong[] Rent(int minimumLength) => new ulong[minimumLength];

            public void Return(ulong[] buffer)
            {
                var allZero = true;
                foreach (var v in buffer)
                {
                    if (v != 0)
                    {
                        allZero = false;
                        break;
                    }
                }

                ReturnedZeroed.Add(allZero);
            }
        }

        /// <summary>
        /// Fails a chosen Rent call to exercise the InitializeLanes failure path, and counts how many buffers were
        /// successfully rented versus returned so a test can assert none leaked.
        /// </summary>
        private sealed class ThrowOnNthRentAllocator : IArgon2MemoryAllocator
        {
            private readonly int _throwOn;
            private int _rents;

            public ThrowOnNthRentAllocator(int throwOn)
            {
                _throwOn = throwOn;
            }

            public int SuccessfulRents { get; private set; }
            public int ReturnCount { get; private set; }

            public ulong[] Rent(int minimumLength)
            {
                if (++_rents == _throwOn)
                {
                    throw new OutOfMemoryException("simulated allocation failure");
                }

                SuccessfulRents++;
                return new ulong[minimumLength];
            }

            public void Return(ulong[] buffer)
            {
                ReturnCount++;
            }
        }

        private static Argon2id NewHasher(byte[] password, IArgon2MemoryAllocator allocator = null)
        {
            var hasher = new Argon2id(password)
            {
                Salt = Encoding.UTF8.GetBytes("a fixed test salt"),
                DegreeOfParallelism = 2,
                MemorySize = 128,
                Iterations = 2,
            };

            if (allocator != null)
            {
                hasher.MemoryAllocator = allocator;
            }

            return hasher;
        }

        [Fact]
        public void CustomAllocatorProducesIdenticalHashAndReturnsEveryBuffer()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");

            byte[] expected;
            using (var def = NewHasher(password))
            {
                expected = def.GetBytes(32);
            }

            var pool = new PoolingAllocator();
            byte[] pooled;
            using (var p = NewHasher(password, pool))
            {
                pooled = p.GetBytes(32);
            }

            Assert.Equal(expected, pooled);                 // identical output regardless of allocator
            Assert.Equal(pool.RentCount, pool.ReturnCount); // every rented buffer was returned
            Assert.True(pool.RentCount >= 2);               // at least one buffer per lane (DegreeOfParallelism)
        }

        [Fact]
        public void CustomAllocatorReusesBuffersAcrossHashes()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            var pool = new PoolingAllocator();

            byte[] first = null;
            for (var i = 0; i < 3; i++)
            {
                using var p = NewHasher(password, pool);
                var result = p.GetBytes(32);
                first ??= result;
                Assert.Equal(first, result); // reused, cleared buffers still yield a stable hash
            }

            Assert.Equal(pool.RentCount, pool.ReturnCount);
            // Buffers are returned between sequential hashes, so the pool never allocates more than the peak
            // number outstanding at once — everything past that is a reuse.
            Assert.Equal(pool.MaxOutstanding, pool.AllocationCount);
            Assert.True(pool.RentCount > pool.AllocationCount);
        }

        [Fact]
        public void WorkingBuffersAreZeroedBeforeBeingReturned()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            var recorder = new ReturnRecordingAllocator();

            using (var p = NewHasher(password, recorder))
            {
                p.GetBytes(32);
            }

            Assert.True(recorder.ReturnedZeroed.Count >= 2);         // at least one buffer per lane
            Assert.All(recorder.ReturnedZeroed, wasZeroed => Assert.True(wasZeroed));
        }

        [Fact]
        public async Task RentedBuffersAreReturnedWhenALaneRentThrows()
        {
            var password = Encoding.UTF8.GetBytes("correct horse battery staple");
            var alloc = new ThrowOnNthRentAllocator(throwOn: 2); // succeed for lane 0, fail renting lane 1

            using var hasher = NewHasher(password, alloc);

            await Assert.ThrowsAsync<OutOfMemoryException>(() => hasher.GetBytesAsync(32));

            Assert.Equal(1, alloc.SuccessfulRents);                 // lane 0 was rented before lane 1 threw
            Assert.Equal(alloc.SuccessfulRents, alloc.ReturnCount); // and it was returned, not leaked
        }
    }
}
