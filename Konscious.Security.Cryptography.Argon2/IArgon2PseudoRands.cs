namespace Konscious.Security.Cryptography
{
    internal interface IArgon2PseudoRands
    {
        ulong PseudoRand(int segment, int prevLane, int prevOffset);
    }
}