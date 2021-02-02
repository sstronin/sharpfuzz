using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpFuzz.Sockets
{
    public sealed class Controller
    {
        private string _hostName;
        private int _controlPort = (-1);
        private int _shmid = (-1);
        private bool _collectLocations;

        #region System interop

        internal sealed class SharedMemoryHandle : SafeHandleMinusOneIsInvalid
        {
            public SharedMemoryHandle() : base(true) { }
            protected override bool ReleaseHandle() => shmdt(handle) == 0;
        }

        [DllImport("libc", SetLastError = true)]
        internal static extern SharedMemoryHandle shmat(int shmid, IntPtr shmaddr, int shmflg);

        [DllImport("libc", SetLastError = true)]
        internal static extern int shmdt(IntPtr shmaddr);
        
        #endregion

        public Controller(string hostName, int controlPort, bool coverage)
        {
            if (String.IsNullOrEmpty(hostName)) throw new ArgumentNullException(nameof(hostName));

            _hostName = hostName;
            _controlPort = controlPort;
            _shmid = Fuzzer.GetShmId();
            _collectLocations = coverage;
        }

        public delegate bool ResultsProcessor(int nRun, string coverage);

        public unsafe void Run(Action<Stream> action, ResultsProcessor iterationCallback)
        {
            if (action is null) throw new ArgumentNullException(nameof(action));

            Logger.Write("Starting fuzzer client");

            using (var stdin = Console.OpenStandardInput())
            using (var stream = new UnclosableStreamWrapper(stdin))
            {
                if (_shmid < 0 )
                {
                    Logger.Write("No afl-fuzz detected, dry run");
                    using (var memory = new UnclosableStreamWrapper(new MemoryStream()))
                    {
                        stream.CopyTo(memory);
                        memory.Seek(0, SeekOrigin.Begin);
                        action(memory);
                    }
                    return;
                }

                var ctrlSocket = new ControlSocket.Client();
                ctrlSocket.Connect(_hostName, _controlPort);

                Logger.Write("Control channel established");

                var initial = true;

                using (var r = new BinaryReader(new AnonymousPipeClientStream(PipeDirection.In, "198")))
                using (var w = new BinaryWriter(new AnonymousPipeClientStream(PipeDirection.Out, "199")))
                {
                    w.Write(0);

                    Logger.Write("Afl-fuzz greeting sent");

                    for (int nRun = 1; ; nRun++)
                    {
                        Logger.Write($"Starting test run {nRun}");

                        var pid = ctrlSocket.StartTest(_collectLocations);
                        if (pid == null) break;

                        Logger.Write($"Agent reports ready on {pid}");

                        var alfReq = r.ReadInt32();
                        Logger.Write($"Afz-fuzz ping request: {alfReq}");

                        w.Write(pid.Value);
                        Logger.Write("Afz-fuzz ping replied");

                        Fuzzer.Fault result;

                        using (var memory = new UnclosableStreamWrapper(new MemoryStream()))
                        {
                            stream.CopyTo(memory);

                            while (true)
                            {
                                memory.Seek(0, SeekOrigin.Begin);

                                Logger.Write($"Executing test {nRun}");
                                result = ExecuteAction(action, memory);
                                if (initial)
                                {
                                    // initial run 
                                    // discard results and retry the test once
                                    Logger.Write("Re-executing initial test");

                                    initial = false;

                                    ctrlSocket.GetStatus(out var c, out var l);

                                    ctrlSocket.StartTest(_collectLocations);
                                    memory.Seek(0, SeekOrigin.Begin);
                                    result = ExecuteAction(action, memory);
                                }

                                Logger.Write($"Test execution result is {result}, requesting remote results");

                                var res = ctrlSocket.GetStatus(out var coverage, out var locations).Value;

                                if (res != (uint)Fuzzer.Fault.None) result = (Fuzzer.Fault)res;

                                if (!iterationCallback(nRun, locations))
                                {
                                    Logger.Write($"Test results were not accepted, repeating run {nRun}");
                                    ctrlSocket.StartTest(_collectLocations);
                                    continue;

                                }

                                if (coverage.Length == Fuzzer.MapSize)
                                {
                                    Logger.Write($"Processing remote results");
                                    using (var shmaddr = shmat(_shmid, IntPtr.Zero, 0))
                                    {
                                        byte* sharedMem = (byte*)shmaddr.DangerousGetHandle();
                                        for (int i = 0; i < coverage.Length; ++i)
                                        {
                                            // simulate instrumentation
                                            sharedMem[i] += coverage[i];
                                        }
                                    }
                                }
                                else
                                {
                                    throw new InvalidDataException("covarage bitmap is invalid");
                                }

                                break;
                            }
                        }

                        Logger.Write($"Reporting run result to afl-fuzz: {result}");
                        w.Write((uint)result);
                    }
                }
            }
        }

        private static Fuzzer.Fault ExecuteAction(Action<Stream> action, Stream stream)
        {
            try
            {
                action(stream);
            }
            catch
            {
                return Fuzzer.Fault.Crash;
            }

            return Fuzzer.Fault.None;
        }
    }
}
