namespace Konscious.Security.Cryptography.Test
{
    using System;
    using System.Text;
    using Xunit;

    /// <summary>
    /// Tests that assert that the non-HW-accelerated version works
    /// </summary>
    public class HMACBlake2BSimdTests
    {
        [Fact]
        public void CorrectlyComputesShortHash512()
        {
            AssertMatch(0x5069230, 9, 512, 512);
        }

        [Fact]
        public void CorrectlyComputesHash256With512BitKey()
        {
            AssertMatch(0x80f39c2, 157, 256, 512);
        }

        [Fact]
        public void CorrectlyComputesHash256With128BitKey()
        {
            AssertMatch(0x12c7361f, 195, 256, 128);
        }

        [Fact]
        public void CorrectlyComputesExactBoundaryHash512()
        {
            AssertMatch(0x5fc00893, 64, 512, 512);
        }

        [Fact]
        public void CorrectlyComputesLongNonBoundary512()
        {
            AssertMatch(0x750a6700, 176, 512, 512);
        }

        [Fact]
        public void CorrectlyComputesLongBoundaryAligned512()
        {
            AssertMatch(0x240f5a03, 640, 512, 512);
        }

        [Fact]
        public void CorrectlyComputesLongBoundary512WithNonBoundaryKey()
        {
            AssertMatch(0x3f078897, 640, 512, 232);
        }

        [Fact]
        public void CorrectlyComputesLongNonBoundary512WithNonBoundaryKey()
        {
            AssertMatch(0xa089e023, 521, 512, 368);
        }

        private void AssertMatch(uint seed, int dataSize, int hashSize, int keySize)
        {
            var rand = new Random((int)seed);
            var data = new byte[dataSize];
            var key = new byte[keySize / 8];

            rand.NextBytes(data);
            rand.NextBytes(key);

            var slow = new HMACBlake2B(key, hashSize, () => new Blake2bSlow(hashSize / 8));
            var normal = new HMACBlake2B(key, hashSize, () => new Blake2bSimd(hashSize / 8));

            slow.Initialize();
            normal.Initialize();

            Assert.Equal(slow.ComputeHash(data), normal.ComputeHash(data));
        }
    }
}