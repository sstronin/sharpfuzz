using System;
using System.Collections.Generic;
using System.Text;

namespace SharpFuzz.Sockets
{
    internal static class Fuzzer
    {
        // afl-fuzz execution status fault codes (only
        // success and crash are currently being used).
        public enum Fault
        {
            None = 0,
            Timeout = 1,
            Crash = 2,
        }

        public static readonly int MapSize = (1 << 16);

        public static int GetShmId()
        {
            var s = Environment.GetEnvironmentVariable("__AFL_SHM_ID");
            if (s != null && Int32.TryParse(s, out var shmid))
            {
                return shmid;
            }
            return (-1);
        }
    }
}
