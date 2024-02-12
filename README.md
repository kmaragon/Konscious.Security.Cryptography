.NET Core Crypto Extensions [![build status](https://ci.appveyor.com/api/projects/status/rqgutdor95f2exav/branch/master?svg=true&branch=master "Appveyor Build Status")](https://ci.appveyor.com/project/kmaragon/konscious-security-cryptography/branch/master)
===============

# Konscious.Security.Cryptography.Blake2

[NuGet package](https://www.nuget.org/packages/Konscious.Security.Cryptography.Blake2/)

An implementation of Blake2 per RFC 7693 in C# and available for .NET core

https://blake2.net/

Usage follows standard types found in System.Security.Cryptography in corefx. Specifically HMAC algorithms.

## Usage

You can use Blake2B interchangeably with any code that uses [`System.Security.Cryptography.HashAlgorithm`](https://docs.microsoft.com/en-us/dotnet/core/api/system.security.cryptography.hashalgorithm#System_Security_Cryptography_HashAlgorithm) Or [`System.Security.Cryptography.HMAC`](https://docs.microsoft.com/en-us/dotnet/core/api/system.security.cryptography.hmac#System_Security_Cryptography_HMAC) And usage is generally consistent with both.

In the project.json:
```JSON
"dependencies":
{
  "Konscious.Security.Cryptography.Blake2": "1.0.*"
}
```
Create an instance of the algorithm:

```C#
using Konscious.Security.Cryptography;
```
```C#
var hashAlgorithm = new Blake2B(512);
```
This will give you a default implementation with no salt that generates a 512 bit key
```
byte[] key = ...
var hashAlgorithm = new Blake2B(key, 512);
```
This will specify some salt to use for the 512 bit hash. Hash size can be any 8 bit aligned value between 8 and 512. The key can be any size between 0 and 64 bytes.

The algorithm needs to be initialized before use:
```C#
hashAlgorithm.Initialize();
```
Then it can be used with any of the standard HashAlgorithm overloads
```C#
Stream p = ...
hashAlgorithm.Hash(p);
```
```C#
byte[] a = ...
hashAlgorithm.Hash(a);
```
And as consistent with any other HMAC implementation:
```C#
hashAlgorithm.Key = otherByteArray;
```

# Konscious.Security.Cryptography.Argon2

[NuGet package](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/)

An implementation of Argon2 winner of PHC

https://password-hashing.net/#argon2

Usage follows standard types found in System.Security.Cryptography in corefx. Specifically DeriveBytes.

## Usage

There is both an Argon2i and Argon2d implementation included in this library. Argon2d is less intensive but subject to timing attacks. That is, if an attacker is appropriately positioned, they can observe the nanosecond differences in processing keys to perform a non-naive brute force attack to reverse the key. Argon2i is non-deterministic so there is no way for an attacker to deduce qualities of the password even if they can observe individual clock cycles and is thus more secure where timing attacks are possible.

Both are standard implementations of the [`System.Security.Cryptography.DeriveBytes`](https://docs.microsoft.com/en-us/dotnet/core/api/system.security.cryptography.derivebytes#System_Security_Cryptography_DeriveBytes) type from corefx. This is commonly used for less secure password hashing via [`System.Security.Cryptography.Rfc2898DeriveBytes`](https://docs.microsoft.com/en-us/dotnet/core/api/system.security.cryptography.rfc2898derivebytes#System_Security_Cryptography_Rfc2898DeriveBytes) which implements the standard PBKDF2 scheme. Argon2 provides a more secure alternative for password hashing.

Project.json:
```JSON
  "dependencies":
  {
      "Konscious.Security.Cryptography.Argon2": "1.0.*"
  }
```

As with Rfc2898DeriveBytes, an Argon2 object is constructed with the password to be hashed:
```C#
using Konscious.Security.Cryptography;
```
```C#
byte[] password = ...
var argon2 = new Argon2i(password);
```
or
```C#
var argon2 = new Argon2d(password);
```
or
```C#
var argon2 = new Argon2id(password);
```
Various attributes can be added to secure the hash:

| Property           | Type      | Required?   |    Description
|--------------------|-----------|-------------|-----------------
|DegreeOfParallelism | int       | REQUIRED    | Argon2 is memory hard and takes advantage of modern processors tendency to be multi-core. It does this by segmenting chunks of memory into lanes. Degree of parallelism specifies how many of these lanes will be used to generate the hash. This value affects the hash itself but can be altered for ideal run time given the processor and number of cores.
|MemorySize          | int       | REQUIRED    | The amount of memory (in KiB) to use to calculate the hash. This is the property that is used to tweak the memory-hard property of Argon2. Please see the Argon2 documentation for more details about how to tweak this, DegreeOfParallelism, and Iterations to suit your needs
|Iterations          | int       | REQUIRED    | The number of iterations to perform to compute the hash. Because of Argon2's higher security, huge values like with PBKDF2 are not as necessary, although multiple iterations are still very much recommended.
|Salt                | byte[]    | RECOMMENDED | Standard Salt value for the Hash Algorithm
|AssociatedData      | byte[]    | OPTIONAL    | Additional associated data to use to compute the hash. This adds another layer of inderection for an attacker to reverse engineer the hash
|KnownSecret         | byte[]    | OPTIONAL    | An additional secret to use for the hash for extra security

And the primary hash method:
````csharp
byte[] GetBytes(int)
````
Which takes the number of bytes to generate. This implementation will accept only up to 1024 bytes as input.

```C#
byte[] salt;
byte[] userUuidBytes;
...
argon2.DegreeOfParallelism = 16;
argon2.MemorySize = 8192;
argon2.Iterations = 40;
argon2.Salt = salt;
argon2.AssociatedData = userUuidBytes;

var hash = argon2.GetBytes(128);
```
