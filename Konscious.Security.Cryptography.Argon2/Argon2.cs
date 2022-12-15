using System.Diagnostics.CodeAnalysis;

namespace Konscious.Security.Cryptography
{
    using System;
    using System.Threading.Tasks;
    using System.Security.Cryptography;

    /// <summary>
    /// An implementation of Argon2 https://github.com/P-H-C/phc-winner-argon2
    /// </summary>
    [SuppressMessage("Microsoft.Performance", "CA1819")]  
    public abstract class Argon2 : DeriveBytes
    {
        /// <summary>
        /// Sets whether this class should run Task operations as single threaded or multy threaded
        /// </summary>
        public bool SingleThreaded { get; set;  }

        /// <summary>
        /// Create an Argon2 for encrypting the given password
        /// </summary>
        /// <param name="password"></param>
        public Argon2(byte[] password)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Argon2 needs a password set", nameof(password));

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
            ValidateParameters(bc);
            var task = Task.Run(async () => await GetBytesAsyncImpl(bc).ConfigureAwait(false) );
            return task.Result;
        }


        /// <summary>
        /// Implementation of GetBytes
        /// </summary>
        public Task<byte[]> GetBytesAsync(int bc)
        {
            ValidateParameters(bc);
            return GetBytesAsyncImpl(bc);
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

        private void ValidateParameters(int bc)
        {
            if (bc > 1024)
                throw new NotSupportedException("Current implementation of Argon2 only supports generating up to 1024 bytes");

            if (Iterations < 1)
                throw new InvalidOperationException("Cannot perform an Argon2 Hash with out at least 1 iteration");

            if (MemorySize < 4)
                throw new InvalidOperationException("Argon2 requires a minimum of 4kB of memory (MemorySize >= 4)");

            if (DegreeOfParallelism < 1)
                throw new InvalidOperationException("Argon2 requires at least 1 thread (DegreeOfParallelism)");
        }

        private Task<byte[]> GetBytesAsyncImpl(int bc)
        {
            var n = BuildCore(bc);
            n.Salt = Salt;
            n.Secret = KnownSecret;
            n.AssociatedData = AssociatedData;
            n.Iterations = Iterations;
            n.MemorySize = MemorySize;
            n.DegreeOfParallelism = DegreeOfParallelism;
            n.SingleThreaded = SingleThreaded;
            return n.Hash(_password);
        }

        private byte[] _password;
    }
}
