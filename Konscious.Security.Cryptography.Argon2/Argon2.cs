namespace Konscious.Security.Cryptography
{
    using System;
    using System.Threading.Tasks;
    using System.Security.Cryptography;

    /// <summary>
    /// An implementation of Argon2 https://github.com/P-H-C/phc-winner-argon2
    /// </summary>
    public abstract class Argon2 : DeriveBytes
    {
        /// <summary>
        /// Create an Argon2 for encrypting the given password
        /// </summary>
        /// <param name="password"></param>
        public Argon2(byte[] password)
        {
            _password = password;
        }

        /// <summary>
        /// Implementation of Reset
        /// </summary>
        public override void Reset()
        {
        }

        /// <summary>
        /// Implementation of GetBytes
        /// </summary>
        public override byte[] GetBytes(int bc)
        {
            return GetBytesAsync(bc).Result;
        }


        /// <summary>
        /// Implementation of GetBytes
        /// </summary>
        public Task<byte[]> GetBytesAsync(int bc)
        {
            if (bc > 1024)
                throw new NotSupportedException("Current implementation of Argon2 only supports generating up to 1024 bytes");

            if (Iterations < 1)
                throw new InvalidOperationException("Cannot perform an Argon2 Hash with out at least 1 iteration");

            if (MemorySize < 4)
                throw new InvalidOperationException("Argon2 requires a minimum of 4kB of memory (MemorySize >= 4)");

            if (DegreeOfParallelism < 1)
                throw new InvalidOperationException("Argon2 requires at least 1 thread (DegreeOfParallelism)");

            var n = BuildCore(bc);
            n.Salt = Salt;
            n.Secret = KnownSecret;
            n.AssociatedData = AssociatedData;
            n.Iterations = Iterations;
            n.MemorySize = MemorySize;
            n.DegreeOfParallelism = DegreeOfParallelism;

            return n.Hash(_password);
        }

        /// <summary>
        /// The password hashing salt
        /// </summary>
        public byte[] Salt { get; set; }

        /// <summary>
        /// An optional secret to use while hashing the Password
        /// </summary>
        public byte[] KnownSecret { get; set; }

        /// <summary>
        /// Any extra associated data to use while hashing the password
        /// </summary>
        public byte[] AssociatedData { get; set; }

        /// <summary>
        /// The number of iterations to apply to the password hash
        /// </summary>
        public int Iterations { get; set; }

        /// <summary>
        /// The number of 1kB memory blocks to use while proessing the hash
        /// </summary>
        public int MemorySize { get; set; }

        /// <summary>
        /// The number of lanes to use while processing the hash
        /// </summary>
        public int DegreeOfParallelism { get; set; }

        internal abstract Argon2Core BuildCore(int bc);

        private byte[] _password;
    }
}