using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace ComparisonHarness
{
    public static class Program
    {
        private readonly static ThreadLocal<Stopwatch> _sw = new ThreadLocal<Stopwatch>(() => new Stopwatch());
        private static string _pythonFilePath = "../../../../PythonHarness/main.py";
        private static readonly (int low, int high) _memCostRange = (4096, 65536);
        private static readonly (int low, int high) _parallelismRange = (1, 12);
        private static readonly (int low, int high) _iterationRange = (1, 5);
        private static readonly (int low, int high) _hashLengthRange = (32, 512);
        private static readonly (int low, int high) _passLengthRange = (4, 128);
        private static readonly Random _random = new();
        private static readonly object _lock = new object();
        private static readonly ConcurrentQueue<(ArgonParams argonParams, string password, string salt)> _failureProps = new();
        private static int _completedThreads;

        public static async Task<int> Main(string[] args)
        {
            if (args.Length != 0)
            {
                _pythonFilePath = args[0];
            }

            await RunTest(100_000, 4);
            return 0;
        }

        private static async Task RunTest(int howManyTests, int parallelCount)
        {
            _completedThreads = 0;
            var threads = new Thread[parallelCount];
            for (var i = 0; i < parallelCount; i++)
            {
                threads[i] = CreateTestThread(howManyTests / parallelCount, i);
                threads[i].Start();
            }

            while (_completedThreads != parallelCount)
            {
                await Task.Delay(100);
            }

            foreach (var (argonParams, password, salt) in _failureProps)
            {
                Console.WriteLine($"FAILED: {argonParams} | {salt} | {password}");
            }

            Console.WriteLine($"Succeeded: {howManyTests - _failureProps.Count}\nFailed: {_failureProps.Count}");
        }

        private static Thread CreateTestThread(int howManyTests, int currentThread)
        {
            return new Thread(() =>
            {
                _sw.Value!.Start();
                for (int i = 0; i < howManyTests; i++)
                {
                    int passLength;
                    lock (_lock)
                    {
                        passLength = _random.Next(_passLengthRange.low, _passLengthRange.high);
                    }

                    var pass = RandomString(passLength);
                    var argonParams = CreateParams();
                    
                    var salt = Guid.NewGuid().ToString();

                    try
                    {
                        var referenceHash = GetCSharpHash(salt, pass, argonParams);
                        
                        var info = new ProcessStartInfo("python", $"{_pythonFilePath} {argonParams.MemoryKb} {argonParams.Parallelism} {argonParams.Iterations} {argonParams.HashLength} { referenceHash} {pass}")
                        {
                            RedirectStandardOutput = true,
                        };
                        using var proc = Process.Start(info);

                        if (proc == null)
                        {
                            Console.WriteLine("Python executable not found");
                            return;
                        }
                        
                        proc.WaitForExit(30_000);

                        if (proc.ExitCode != 0)
                        {
                            Console.WriteLine($"Id:{currentThread}/{i}: FAILED");
                            _failureProps.Enqueue((argonParams, pass, salt));
                        }
                        else
                        {
                            Console.WriteLine($"TestId: {currentThread,3}/{i,-3}: SUCCEEDED in {_sw.Value!.ElapsedMilliseconds}ms");
                            _sw.Value.Restart();
                        }
                    }
                    catch (Exception)
                    {
                        _failureProps.Enqueue((argonParams, pass, salt));
                    }
                }

                Interlocked.Increment(ref _completedThreads);
            });
        }

        private static string GetCSharpHash(string salt, string pass, ArgonParams argonParams)
        {
            var asBytes = Encoding.UTF8.GetBytes(pass);
            using var argon = new Argon2id(asBytes)
            {
                Iterations = argonParams.Iterations,
                DegreeOfParallelism = argonParams.Parallelism,
                MemorySize = argonParams.MemoryKb,
            };

            argon.Salt = Encoding.UTF8.GetBytes(salt);
            //Console.WriteLine($"Salt is: {salt}");
            var hash = argon.GetBytes(argonParams.HashLength);
            return argonParams.ToString(argon.Salt, hash);
        }

        private static ArgonParams CreateParams()
        {
            return new ArgonParams
            {
                Iterations = ValueFromRange(_iterationRange),
                MemoryKb = ValueFromRange(_memCostRange),
                Parallelism = ValueFromRange(_parallelismRange),
                HashLength = ValueFromRange(_hashLengthRange)
            };
        }

        private static int ValueFromRange((int low, int high) range)
        {
            lock(_lock)
            {
                return _random.Next(range.low, range.high);
            }
        }

        private static string RandomString(int len)
        {
            var sb = new StringBuilder(len);
            lock(_lock)
            {
                for (int i = 0; i < len; i++)
                {
                    sb.Append((char)_random.Next(64, 122));
                }
            }

            return sb.ToString();
        }
    }

    public record ArgonParams
    {
        public int MemoryKb { get; init; }
        public int Parallelism { get; init; }
        public int Iterations { get; init; }
        public int HashLength { get; init; }

        public override string ToString()
        {
            return JsonSerializer.Serialize(this);
        }

        public string ToString(byte[] salt, byte[] hash)
        {
            return $"$argon2id$v=19$m={MemoryKb},t={Iterations},p={Parallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash).Replace("=", "")}";
        }
    }
}
