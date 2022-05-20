namespace Konscious.Security.Cryptography
{
    using System;

    /// <summary>
    /// The implementation of Argon2d for use in the crypto library
    /// </summary>
    internal class Argon2dCore : Argon2Core
    {
        internal class PseudoRands : IArgon2PseudoRands
        {
            private readonly Argon2Lane[] _lanes;

            public PseudoRands(Argon2Lane[] lanes)
            {
                _lanes = lanes;
            }

            public ulong PseudoRand(int segment, int prevLane, int prevOffset)
            {
                return _lanes[prevLane][prevOffset].Span[0];
            }
        }

        public Argon2dCore(int hashSize)
            : base(hashSize)
        {

        }

        public override int Type
        {
            get
            {
                return 0;
            }
        }

        internal override IArgon2PseudoRands GenerateState(Argon2Lane[] lanes, int segmentLength, int pass, int lane, int slice)
        {
            return new PseudoRands(lanes);
        }
    }
}