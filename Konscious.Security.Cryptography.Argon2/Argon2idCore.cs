namespace Konscious.Security.Cryptography
{
    /// <summary>
    /// The implementation of Argon2d for use in the crypto library
    /// </summary>
    internal class Argon2idCore : Argon2Core
    {
        private Argon2dCore datadep_;
        private Argon2iCore dataindep_;
        private const uint ARGON2_SYNC_POINTS = 4;
        
        public Argon2idCore(int hashSize) :
            base(hashSize)
        {
            datadep_ = new Argon2dCore(hashSize);
            dataindep_ = new Argon2iCore(hashSize);
        }

        public override int Type
        {
            get
            {
                return 2;
            }
        }

        internal override IArgon2PseudoRands GenerateState(Argon2Lane[] lanes, int segmentLength, int pass, int lane, int slice)
        {
            if ((pass == 0) && (slice < (ARGON2_SYNC_POINTS / 2)))
                return dataindep_.GenerateState(lanes, segmentLength, pass, lane, slice);
            return datadep_.GenerateState(lanes, segmentLength, pass, lane, slice);
        }
    }
}