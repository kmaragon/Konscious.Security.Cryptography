using System;

namespace Konscious.Security.Cryptography;

internal class ModifiedBlake2Reference : ModifiedBlake2Base
{
    private static ulong Rotate(ulong x, int y)
    {
        return (((x) >> (y)) ^ ((x) << (64 - (y))));
    }

    private static void ModifiedG(Span<ulong> v, int a, int b, int c, int d)
    {
        var t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
        v[a] = v[a] + v[b] + 2 * t;

        v[d] = Rotate(v[d] ^ v[a], 32);

        t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
        v[c] = v[c] + v[d] + 2 * t;

        v[b] = Rotate(v[b] ^ v[c], 24);

        t = (v[a] & 0xffffffff) * (v[b] & 0xffffffff);
        v[a] = v[a] + v[b] + 2 * t;


        v[d] = Rotate(v[d] ^ v[a], 16);

        t = (v[c] & 0xffffffff) * (v[d] & 0xffffffff);
        v[c] = v[c] + v[d] + 2 * t;

        v[b] = Rotate(v[b] ^ v[c], 63);
    }

    private static void DoRoundColumns(Span<ulong> v, int i)
    {
        i *= 16;
        ModifiedG(v, i, i + 4, i + 8, i + 12);
        ModifiedG(v, i + 1, i + 5, i + 9, i + 13);
        ModifiedG(v, i + 2, i + 6, i + 10, i + 14);
        ModifiedG(v, i + 3, i + 7, i + 11, i + 15);
        ModifiedG(v, i, i + 5, i + 10, i + 15);
        ModifiedG(v, i + 1, i + 6, i + 11, i + 12);
        ModifiedG(v, i + 2, i + 7, i + 8, i + 13);
        ModifiedG(v, i + 3, i + 4, i + 9, i + 14);
    }

    private static void DoRoundRows(Span<ulong> v, int i)
    {
        i *= 2;
        ModifiedG(v, i, i + 32, i + 64, i + 96);
        ModifiedG(v, i + 1, i + 33, i + 65, i + 97);
        ModifiedG(v, i + 16, i + 48, i + 80, i + 112);
        ModifiedG(v, i + 17, i + 49, i + 81, i + 113);
        ModifiedG(v, i, i + 33, i + 80, i + 113);
        ModifiedG(v, i + 1, i + 48, i + 81, i + 96);
        ModifiedG(v, i + 16, i + 49, i + 64, i + 97);
        ModifiedG(v, i + 17, i + 32, i + 65, i + 112);
    }

    public override void Compress(Span<ulong> dest, ReadOnlySpan<ulong> refb, ReadOnlySpan<ulong> prev)
    {
        Span<ulong> tmpblock = stackalloc ulong[dest.Length];
        for (var n = 0; n < 128; ++n)
        {
            tmpblock[n] = refb[n] ^ prev[n];
            dest[n] ^= tmpblock[n];
        }

        for (var i = 0; i < 8; ++i)
            DoRoundColumns(tmpblock, i);
        for (var i = 0; i < 8; ++i)
            DoRoundRows(tmpblock, i);

        for (var n = 0; n < 128; ++n)
            dest[n] ^= tmpblock[n];
    }

    public override bool IsSupported => true;
}