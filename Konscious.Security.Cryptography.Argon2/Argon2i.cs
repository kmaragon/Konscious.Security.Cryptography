namespace Konscious.Security.Cryptography
{
    /// <summary>
    /// An implementation of Argon2 https://github.com/P-H-C/phc-winner-argon2
    /// </summary>
    public class Argon2i : Argon2
    {
        /// <summary>
        /// Create an Argon2 for encrypting the given password using Argon2i
        /// </summary>
        /// <param name="password"></param>
        public Argon2i(byte[] password)
            : base(password)
        {
        }

        internal override Argon2Core BuildCore(int bc)
        {
            return new Argon2iCore(bc);
        }

    }
}