using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpFuzz.Sockets
{
    internal class ControlSocket
    {
        public class Client
        {
            private Socket _socket;

            public void Connect(string host, int port)
            {
                Logger.Write($"Fuzzer client connecting to {host}:{port}");

                var addreses = IPAddress.TryParse(host, out var address)?
                    new IPAddress[] { address } : Dns.GetHostEntry(host).AddressList;

                _socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _socket.Connect(addreses, port);
                
                Logger.Write($"Fuzzer client connected");
            }

            public uint? StartTest(bool getLocations)
            {
                Logger.Write($"Fuzzer client set server on test ({getLocations})");
                _socket.Send(BitConverter.GetBytes(getLocations ? (uint)1 : (uint)2));
                var buffer = new byte[sizeof(uint)];
                _socket.Receive(buffer);
                var pid = BitConverter.ToUInt32(buffer, 0);
                Logger.Write($"Fuzzer client get server confirmation from {pid}");
                return pid;
            }

            public int? GetStatus(out byte[] coverage, out string locations)
            {
                using (var ns = new NetworkStream(_socket))
                using (var rs = new BinaryReader(ns))
                {
                    Logger.Write($"Fuzzer client requesting test results");
                    ns.Write(BitConverter.GetBytes((uint)0), 0, sizeof(uint));

                    var status = rs.ReadInt32();
                    Logger.Write($"Fuzzer client received test status {status}");

                    coverage = rs.ReadBytes(Fuzzer.MapSize);
                    Logger.Write($"Fuzzer client received coverage");

                    var locationLength = rs.ReadInt32();
                    if (locationLength > 0)
                    {
                        var locationBuffer = rs.ReadBytes(locationLength);
                        locations = Encoding.UTF8.GetString(locationBuffer);
                        Logger.Write($"Fuzzer client received locations");
                    }
                    else
                    {
                        locations = String.Empty;
                    }

                    return status;
                }
            }
        }
        public class Server
        {
            private Socket _socket;
            private Socket _listener;

            public Server(int port)
            {
                _listener = new Socket(SocketType.Stream, ProtocolType.Tcp);
                _listener.Bind(new IPEndPoint(0, port));
                _listener.Listen(3);
                Logger.Write($"Fuzzer server listening on {port}");
            }

            public bool ProcessStartTest(Action<bool> prepare)
            {
                Logger.Write($"Fuzzer server awaiting commands");
                var buffer = new byte[sizeof(int)];
                _socket.Receive(buffer);
                var command = BitConverter.ToInt32(buffer, 0);
                Logger.Write($"Fuzzer server received command {command}");

                if (command == 0) return false;
                prepare(command == 1);
                _socket.Send(BitConverter.GetBytes(Process.GetCurrentProcess().Id));
                Logger.Write($"Fuzzer server ready for a test");

                return true;
            }

            public delegate int StatusCallback(out byte[] coverage, out string locations);

            public void ProcessGetStatus(StatusCallback statusCallback)
            {
                Logger.Write($"Fuzzer server waits a request");
                var buffer = new byte[sizeof(int)];
                _socket.Receive(buffer);
                var command = BitConverter.ToInt32(buffer, 0);
                if (command == 0)
                {
                    Logger.Write($"Fuzzer server received request {command}");

                    var res = statusCallback(out var coverage, out var locations);
                    Logger.Write($"Fuzzer server processing test status {res} {locations?.Length}");

                    var locationsBuff = Encoding.UTF8.GetBytes(locations);

                    using (var ns = new NetworkStream(_socket))
                    using (var ws = new BinaryWriter(ns))
                    {
                        ws.Write(res);
                        ws.Write(coverage, 0, Fuzzer.MapSize);
                        ws.Write(locationsBuff.Length);
                        ws.Write(locationsBuff);
                        ws.Flush();
                    }

                    Logger.Write($"Fuzzer server sent test results");
                }
            }

            internal bool WaitConnection()
            {
                _socket = _listener.Accept();
                Logger.Write($"Sockets fuzzer connected");
                return true;
            }

            internal void Abort()
            {
                _socket.Close();
            }
        }
    }
}
