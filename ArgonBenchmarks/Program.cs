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
                MemorySize = RamKiloBytes,
                Salt = Guid.NewGuid().ToByteArray()
            };

            return await _argon.GetBytesAsync(128);
        }

        [ParamsSource(nameof(IterationValues))]
        public int Iterations { get; set; }

        [ParamsSource(nameof(RamKilobytesValues))]
        public int RamKiloBytes { get; set; }

        public IEnumerable<int> RamKilobytesValues => Enumerable.Range(0, 16).Select(x => x * 1024 * 4 + 65536);

        public IEnumerable<int> IterationValues => Enumerable.Range(1, 5).Select(x => x*2);
    }
}
