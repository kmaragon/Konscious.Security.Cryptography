using Konscious.Security.Cryptography;
using System;
using System.Text;
using BenchmarkDotNet.Attributes;
using System.Threading.Tasks;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Diagnosers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;

namespace ArgonBenchmarks
{
    internal class Program
    {
        public static void Main()
        {
            BenchmarkRunner.Run<ArgonBenchmarks>();
        }
    }

    public class Config : ManualConfig
    {
        public Config()
        {
            //Run with intrinsics disabled
            AddJob(
                Job.Default
                .WithEnvironmentVariable(new EnvironmentVariable("COMPlus_EnableSSE2", "0"))
                .WithRuntime(CoreRuntime.Core60)
                .AsBaseline());

            // Run with intrinsics
            AddJob(
               Job.Default.WithRuntime(CoreRuntime.Core60));

            AddJob(
               Job.Default.WithRuntime(CoreRuntime.Core50));
        }
    }

    [Config(typeof(Config))]
    [MemoryDiagnoser]
    [JsonExporterAttribute.BriefCompressed, CsvExporter(BenchmarkDotNet.Exporters.Csv.CsvSeparator.CurrentCulture), HtmlExporter]
    public class ArgonBenchmarks
    {
        private readonly string _toHash = "iamapasswordthatneedshashing";
        private Argon2id _argon;

        [Benchmark]
        public byte[] GetHash()
        {
            return _argon.GetBytes(128);
        }

        [IterationSetup]
        public void IterationSetup()
        {
            _argon = new Argon2id(Encoding.UTF8.GetBytes(_toHash))
            {
                DegreeOfParallelism = 4,
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
        //    .Concat(new[] { 1048576, 4 * 1048576 });

        //CN -- Quick
        public IEnumerable<int> RamKilobytesValues => Enumerable.Range(0, 4).Select(x => x * 1024 * 8 + 65536);


        //CN -- Full
        //public IEnumerable<int> IterationValues => Enumerable.Range(1, 5).Select(x => 2*x - 1);

        //CN -- Quick
        public IEnumerable<int> IterationValues => Enumerable.Range(1, 2).Select(x => x + (x - 1) * 4);
    }
    
    [MemoryDiagnoser, ThreadingDiagnoser]
    public class BlitMarks
    {
        private readonly byte[] _toBlitWithBytes = new byte[64];
        private readonly byte[] _bytes = new byte[128 * 8 * 1024];
        private ulong[] _longs;

        private static readonly Random _random = new Random();

        [Benchmark]
        public void Blit()
        {
            for (var i = 1; i < 100_000_000; i++)
            {
                _longs.AsSpan().Blit(_toBlitWithBytes);
            }
        }

        [IterationSetup]
        public void IterationSetup()
        {
            _random.NextBytes(_bytes);
            _longs = MemoryMarshal.Cast<byte, ulong>(_bytes).ToArray();
            _random.NextBytes(_toBlitWithBytes);
        }
    }
}
