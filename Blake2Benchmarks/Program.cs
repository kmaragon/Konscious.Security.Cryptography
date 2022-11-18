using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Konscious.Security.Cryptography;
using Perfolizer.Mathematics.Randomization;
using System;
using System.Threading.Tasks;

BenchmarkRunner.Run<BlakeSimdBenchmark>();

var b = new BlakeSimdBenchmark() { Size = 32_000_000 };
b.Setup();
b.GetHash();

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net60)]
[JsonExporterAttribute.BriefCompressed, CsvExporter(BenchmarkDotNet.Exporters.Csv.CsvSeparator.CurrentCulture), HtmlExporter]
public class BlakeSimdBenchmark
{
    private readonly HMACBlake2B _blake2b = new HMACBlake2B(256/8);
    private byte[] _data;

    [GlobalSetup]
    public void Setup()
    {
        Random rnd = new Random(42);
        _data = new byte[Size];
        rnd.NextBytes(_data);
    }

    [Params(
        (int)3,
   (int)1E+2,  // 100 bytes
   (int)1E+3,  // 1 000 bytes = 1 KB
   (int)1E+4  // 10 000 bytes = 10 KB
   )]
    public int Size { get; set; }

    [Benchmark]
    public byte[] GetHash()
    {
        return _blake2b.ComputeHash(_data);
    }
}