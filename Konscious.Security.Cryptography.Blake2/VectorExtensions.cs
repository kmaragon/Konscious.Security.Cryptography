#if NET6_0_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace Konscious.Security.Cryptography;

internal static class VectorExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<T> LoadUnsafeVector128<T>(ref T source)
        where T : struct
    {
        return Unsafe.ReadUnaligned<Vector128<T>>(ref Unsafe.As<T, byte>(ref source));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<T> LoadUnsafeVector256<T>(ref T source)
        where T : struct
    {
        return Unsafe.ReadUnaligned<Vector256<T>>(ref Unsafe.As<T, byte>(ref source));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<T> LoadUnsafeVector256<T>(ref T source, nuint elementOffset)
        where T : struct
    {
        source = ref Unsafe.Add(ref source, (nint)elementOffset);
        return Unsafe.ReadUnaligned<Vector256<T>>(ref Unsafe.As<T, byte>(ref source));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void StoreUnsafe<T>(this Vector256<T> source, ref T pdestination)
        where T : struct
    {
        Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref pdestination), source);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void StoreUnsafe<T>(this Vector256<T> source, ref T Tdestination, nuint elementOffset)
        where T : struct
    {
        Tdestination = ref Unsafe.Add(ref Tdestination, (nint)elementOffset);
        Unsafe.WriteUnaligned(ref Unsafe.As<T, byte>(ref Tdestination), source);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<T> BroadcastVector128ToVector256<T>(ref T ptr) where T : struct
    {
        var vector = Unsafe.ReadUnaligned<Vector128<T>>(ref Unsafe.As<T, byte>(ref ptr));
        Vector256<T> result = vector.ToVector256Unsafe();
        return result.WithUpper(vector);
    }
}

#endif