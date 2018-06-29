namespace Konscious.Security.Cryptography.Test
{
    using System;
    using System.Text;
    using Xunit;

    /// <summary>
    /// Tests that assert that the non-HW-accelerated version works
    /// </summary>
    public class HMACBlake2BNormalTests
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

        [Fact]
        public void AutoInitializesBlake2BIfUserDoesNotInitialize()
        {
            var subject = new HMACBlake2B(512);
            var data = subject.ComputeHash(Encoding.UTF8.GetBytes("Hello"));

            Assert.Equal(new byte[] {
                0xef, 0x15, 0xea, 0xf9, 0x2d, 0x5e, 0x33, 0x53, 0x45, 0xa3, 0xe1, 0xd9, 0x77, 0xbc, 0x7d, 0x87,
                0x97, 0xc3, 0xd2, 0x75, 0x71, 0x7c, 0xc1, 0xb1, 0x0a, 0xf7, 0x9c, 0x93, 0xcd, 0xa0, 0x1a, 0xeb,
                0x2a, 0x0c, 0x59, 0xbc, 0x02, 0xe2, 0xbd, 0xf9, 0x38, 0x0f, 0xd1, 0xb5, 0x4e, 0xb9, 0xe1, 0x66,
                0x90, 0x26, 0x93, 0x0c, 0xcc, 0x24, 0xbd, 0x49, 0x74, 0x8e, 0x65, 0xf9, 0xa6, 0xb2, 0xee, 0x68},
                data);
        }

        private static void AssertMatch(uint seed, int dataSize, int hashSize, int keySize)
        {
            var rand = new Random((int)seed);
            var data = new byte[dataSize];
            var key = new byte[keySize / 8];

            rand.NextBytes(data);
            rand.NextBytes(key);

            var slow = new HMACBlake2B(key, hashSize, () => new Blake2bSlow(hashSize / 8));
            var normal = new HMACBlake2B(key, hashSize, () => new Blake2bNormal(hashSize / 8));
            var deflt = new HMACBlake2B(key, hashSize);

            slow.Initialize();
            normal.Initialize();
            deflt.Initialize();

            Assert.Equal(slow.ComputeHash(data), normal.ComputeHash(data));
            Assert.Equal(deflt.ComputeHash(data), normal.ComputeHash(data));
        }
    }
}