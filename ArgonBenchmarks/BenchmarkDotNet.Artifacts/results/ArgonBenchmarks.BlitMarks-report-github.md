``` ini

BenchmarkDotNet=v0.13.1, OS=Windows 10.0.19043.1288 (21H1/May2021Update)
AMD Ryzen 9 5900X, 1 CPU, 24 logical and 12 physical cores
.NET SDK=6.0.100-rc.2.21505.57
  [Host]     : .NET 5.0.11 (5.0.1121.47308), X64 RyuJIT
  Job-CZVYKO : .NET 5.0.11 (5.0.1121.47308), X64 RyuJIT

InvocationCount=1  UnrollFactor=1  

```
| Method |     Mean |   Error |  StdDev | Completed Work Items | Lock Contentions | Allocated |
|------- |---------:|--------:|--------:|---------------------:|-----------------:|----------:|
|   Blit | 647.7 ms | 1.13 ms | 0.95 ms |               2.0000 |                - |         - |
