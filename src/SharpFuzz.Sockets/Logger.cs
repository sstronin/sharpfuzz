using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace SharpFuzz.Sockets
{
    public static class Logger
    {
        static private TraceSource _ts;
        static Logger()
        {
            _ts = new TraceSource("SocketFuzzer");
            _ts.Switch = new SourceSwitch("fuzzer");
            _ts.Switch.Level = SourceLevels.All;
            Trace.AutoFlush = true;
        }

        public static TraceListener AddFileListener(string path)
        {
            var logPath = Environment.ExpandEnvironmentVariables(path);
            var listener = new TextWriterTraceListener(File.AppendText(logPath), "fuzzer");

            listener.Filter = new SourceFilter(_ts.Name);

            _ts.Listeners.Add(listener);
            return listener;
        }

        public static void Write(string message)
        {
            _ts.TraceInformation(
                $"{DateTime.Now:HH:MM:ss.fff} {Process.GetCurrentProcess().Id} {message}");
        }
    }
}
