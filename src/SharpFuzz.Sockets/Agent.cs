using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SharpFuzz.Sockets
{
    public sealed class Agent
    {
        private int _controlPort = (-1);

        public Agent(int controlPort)
        {
            _controlPort = controlPort;
        }

        public unsafe void Run(Func<uint> statusCallback)
        {
            Logger.Write($"Initializing fuzzing monitor");

            var traceBuffer = new byte[Fuzzer.MapSize];
            var locations = new ConcurrentDictionary<string, ConcurrentDictionary<int,int> >();
            var getLocations = false;

            fixed (byte* traceArea = traceBuffer)
                using (var traceWrapper = new TraceWrapper(
                    traceArea,
                    (i, s) => {
                        if(getLocations)
                        {
                            var entry = locations.GetOrAdd(s, new ConcurrentDictionary<int, int>());
                            entry.GetOrAdd(i, 1);
                        }
                    }))
                {
                    var ctrlSocket = new ControlSocket.Server(_controlPort);
                    Logger.Write($"Server listening");

                    while (ctrlSocket.WaitConnection())
                    {
                        Logger.Write($"Client connected");
                        try
                        {
                            while (ctrlSocket.ProcessStartTest(
                                (collectLocations) =>
                                {
                                    getLocations = collectLocations;
                                    locations.Clear();
                                    traceWrapper.ResetPrevLocation();
                                    traceBuffer.Initialize();
                                    Logger.Write($"State was reset");
                                }))
                            {
                                Logger.Write($"Gathering state");
                                ctrlSocket.ProcessGetStatus((out byte[] c, out string l) =>
                                {
                                    Logger.Write($"Reporting state");
                                    c = new byte[traceBuffer.Length];
                                    traceBuffer.CopyTo(c,0);
                                    l = string.Join(Environment.NewLine, 
                                        locations.Select((i) => $"{i.Key};{i.Value.Count}"));
                                    return (int)statusCallback();
                                });
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write($"Client communication error: {e.ToString()}");
                            ctrlSocket.Abort();
                        }
                    }
                }
        }
    }
}
