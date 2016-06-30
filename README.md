Blake2 for C#
===============

An implementation of Blake2 per RFC 7693 in C# and available for .NET core

https://blake2.net/

Usage follows standard types found in System.Security.Cryptography in corefx.

Currently the only implementation is an HMAC derivative. But a simple HashAlgorithm derivative
for basic Blake2 sums will be available soon as it requires minimal additional work.