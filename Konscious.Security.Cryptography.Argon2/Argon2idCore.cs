namespace Konscious.Security.Cryptography
{
    /// <summary>
    /// The implementation of Argon2d for use in the crypto library
    /// </summary>
    internal class Argon2idCore : Argon2iCore
    {
        private const uint ARGON2_SYNC_POINTS = 4;
        
        public Argon2idCore(int hashSize) :
            base(hashSize)
        { }

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
                return base.GenerateState(lanes, segmentLength, pass, lane, slice);
            return new Argon2dCore.PseudoRands(lanes);
        }
    }
}