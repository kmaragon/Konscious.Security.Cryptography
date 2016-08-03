namespace Konscious.Security.Cryptography
{
    using System;

    /// <summary>
    /// The implementation of Argon2i for use in the crypto library
    /// </summary>
    internal class Argon2iCore : Argon2Core
    {
        public Argon2iCore(int hashSize)
            : base(hashSize)
        {

        }

        public override int Type
        {
            get
            {
                return 1;
            }
        }

        internal override IArgon2PseudoRands GenerateState(Argon2Lane[] lanes, int pass, int lane, int slice)
        {
            return null;
        }
    }
}