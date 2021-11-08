namespace Konscious.Security.Cryptography
{
    using System;

    /// <summary>
    /// The implementation of Argon2i for use in the crypto library
    /// </summary>
    internal class Argon2iCore : Argon2Core
    {
        private readonly static Memory<ulong> _zeroBlock = new Memory<ulong>(new ulong[128]);

        internal class PseudoRands : IArgon2PseudoRands
        {
            private ulong[] _rands;

            public PseudoRands(ulong[] rands)
            {
                _rands = rands;
            }

            public ulong PseudoRand(int segment, int prevLane, int prevOffset)
            {
                return _rands[segment];
            }
        }

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

        internal override IArgon2PseudoRands GenerateState(Argon2Lane[] lanes, int segmentLength, int pass, int lane, int slice)
        {
            var rands = new ulong[segmentLength];

            var ulongRaw = new Memory<ulong>(new ulong[384]);
            var inputBlock = ulongRaw[..128].Span;
            var addressBlock = ulongRaw[128..256].Span;
            var tmpBlock = ulongRaw[256..384].Span;

            inputBlock[0] = (ulong)pass;
            inputBlock[1] = (ulong)lane;
            inputBlock[2] = (ulong)slice;
            inputBlock[3] = (ulong)MemorySize;
            inputBlock[4] = (ulong)Iterations;
            inputBlock[5] = (ulong)Type;

            for (var i = 0; i < segmentLength; i++)
            {
                var ival = i % 128;
                if (ival == 0)
                {
                    inputBlock[6]++;
                    tmpBlock.Fill(0);
                    addressBlock.Fill(0);

                    Compress(tmpBlock, inputBlock, _zeroBlock.Span);
                    Compress(addressBlock, tmpBlock, _zeroBlock.Span);
                }

                rands[i] = addressBlock[ival];
            }

            return new PseudoRands(rands);
        }
    }
}