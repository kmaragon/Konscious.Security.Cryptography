using Konscious.Security.Cryptography;
using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using System.Threading.Tasks;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using System.Collections.Generic;
using System.Linq;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using System.Runtime.InteropServices;

namespace ArgonBenchmarks
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<ArgonBenchmarks>();
        }
    }

    public class ArgonConfig : ManualConfig
    {
        public ArgonConfig()
        {
            AddDiagnoser(MemoryDiagnoser.Default);
            AddDiagnoser(ThreadingDiagnoser.Default);
        }
    }

    [MemoryDiagnoser, ThreadingDiagnoser]
    [JsonExporterAttribute.BriefCompressed, CsvExporter(BenchmarkDotNet.Exporters.Csv.CsvSeparator.CurrentCulture)]
    public class ArgonBenchmarks
    {
        private readonly string _toHash = "iamapasswordthatneedshashing";
        private Argon2id _argon;

        [Benchmark]
        public async Task<byte[]> GetHashAsync()
        {
            return await _argon.GetBytesAsync(128);
        }

        [IterationSetup]
        public void IterationSetup()
        {
            _argon = new Argon2id(Encoding.UTF8.GetBytes(_toHash))
            {
                DegreeOfParallelism = 1,
                Iterations = Iterations,
                MemorySize = RamKilobytes,
                Salt = Guid.NewGuid().ToByteArray()
            };
        }

        [ParamsSource(nameof(IterationValues))]
        public int Iterations { get; set; }

        [ParamsSource(nameof(RamKilobytesValues))]
        public int RamKilobytes { get; set; }

        //CN - Full
        //public IEnumerable<int> RamKilobytesValues => Enumerable.Range(0, 16)
        //    .Select(x => x * 1024 * 4 + 65536)
        //    .Append(1048576)
        //    .Append(4* 1048576);

        //CN -- Quick
        public IEnumerable<int> RamKilobytesValues => new List<int> { 1048576 };//Enumerable.Range(0, 4).Select(x => x * 1024 * 8 + 65536);


        //CN -- Full
        public IEnumerable<int> IterationValues => Enumerable.Range(1, 5).Select(x => (x-1)*2 +1);

        //CN -- Quick
        //public IEnumerable<int> IterationValues => Enumerable.Range(1, 2).Select(x => x + (x - 1) * 4);
    }
    
    [MemoryDiagnoser, ThreadingDiagnoser]
    public class BlitMarks
    {
        private Argon2Memory _memory;
        private byte[] _toBlitWithBytes = new byte[64];

        private static readonly Random _random = new Random();

        [Benchmark]
        public void Blit()
        {
            for (var i = 1; i < 100_000_000; i++)
            {
                _memory.Span.Blit(_toBlitWithBytes);
            }
        }

        [IterationSetup]
        public void IterationSetup()
        {
            var bytes = new byte[128 * 8 * 1024];
            _random.NextBytes(bytes);
            var longs = MemoryMarshal.Cast<byte, ulong>(bytes).ToArray();
            _random.NextBytes(_toBlitWithBytes);
            _memory = new Argon2Memory(longs);
        }
    }
}
