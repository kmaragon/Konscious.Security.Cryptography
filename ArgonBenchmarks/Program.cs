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
    [JsonExporterAttribute.BriefCompressed]
    public class ArgonBenchmarks
    {
        private readonly string _toHash = "iamapasswordthatneedshashing";
        private Argon2id _argon;

        [Benchmark]
        public async Task<byte[]> GetHashAsync()
        {
            _argon = new Argon2id(Encoding.UTF8.GetBytes(_toHash))
            {
                DegreeOfParallelism = 4,
                Iterations = Iterations,
                MemorySize = RamKilobytes,
                Salt = Guid.NewGuid().ToByteArray()
            };

            return await _argon.GetBytesAsync(128);
        }

        [ParamsSource(nameof(IterationValues))]
        public int Iterations { get; set; }

        [ParamsSource(nameof(RamKilobytesValues))]
        public int RamKilobytes { get; set; }

        //CN - Full
        //public IEnumerable<int> RamKilobytesValues => Enumerable.Range(0, 16).Select(x => x * 1024 * 4 + 65536);

        //CN -- Quick
        public IEnumerable<int> RamKilobytesValues => Enumerable.Range(0, 4).Select(x => x * 1024 * 8 + 65536);


        //CN -- Full
        //public IEnumerable<int> IterationValues => Enumerable.Range(1, 5).Select(x => x*2);

        //CN -- Quick
        public IEnumerable<int> IterationValues => Enumerable.Range(1, 2).Select(x => x + (x - 1) * 4);
    }
}
