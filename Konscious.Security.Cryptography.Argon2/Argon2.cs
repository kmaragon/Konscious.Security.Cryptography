namespace Konscious.Security.Cryptography
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// An implementation of Argon2 https://github.com/P-H-C/phc-winner-argon2
    /// </summary>
    public class Argon2 : DeriveBytes
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
            var n = new Argon2iCore(bc);
            n.Initialize(_password);
            throw new NotImplementedException();
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

        private byte[] _password;
    }
}