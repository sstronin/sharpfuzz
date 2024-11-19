using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SharpFuzz.CommandLine
{
	public class Program
	{
		private const string Usage = @"Usage: sharpfuzz [path-to-assembly] [prefix ...]

path-to-assembly:
  The path to an assembly .dll file to instrument.

prefix:
  The class or the namespace to instrument.
  If not present, all types in the assembly will be instrumented.
  At least one prefix is required when instrumenting System.Private.CoreLib.
  
Examples:
  sharpfuzz Newtonsoft.Json.dll
  sharpfuzz System.Private.CoreLib.dll System.Number
  sharpfuzz System.Private.CoreLib.dll System.DateTimeFormat System.DateTimeParse";

		public static int Main(string[] args)
		{
			if (args.Length == 0)
			{
				Console.WriteLine(Usage);
				return 0;
			}

			string path = args[0];
			string[] files;

			if(path.Contains("*") || path.Contains("?"))
            {
				var directory = Path.GetDirectoryName(path);
				if (String.IsNullOrEmpty(directory)) directory = @".\";
				files = Directory.GetFiles(directory, Path.GetFileName(path));
				if (files.Length == 0)
				{
					Console.Error.WriteLine("Files were not found.");
					return 1;
				}
			}
			else
            {
				if (!File.Exists(path))
				{
					Console.Error.WriteLine("Specified file does not exist.");
					return 1;
				}

				files = new string[] { path };
			}
			var include = new List<string>();
			var exclude = new List<string>();

			if(Environment.GetEnvironmentVariable("SHARPFUZZ_INSTRUMENT_MIXED_MODE_ASSEMBLIES") is null)
			{
                Options.Value.InstrumentMixedModeAssemblies = true;
            }

            foreach (var arg in args.Skip(1))
			{
				// This feature is necessary for me, but it's not documented on purpose,
				// because I don't want to complicate things further for the users.
				if (arg.StartsWith("-"))
				{
					exclude.AddRange(arg.Substring(1).Trim().Split(',', StringSplitOptions.RemoveEmptyEntries));
				}
				else if(arg.StartsWith("+"))
				{
					include.AddRange(arg.Substring(1).Split(',', StringSplitOptions.RemoveEmptyEntries));
				}
				else if (arg.StartsWith("/exclude:", StringComparison.InvariantCultureIgnoreCase))
				{
					exclude.AddRange(File.ReadAllLines(arg.Substring(9))
						.Select(i => i.Substring(0, i.IndexOf(':') > 0 ? i.IndexOf(" :") : i.Length).Trim())
						.Where(i => !String.IsNullOrWhiteSpace(i)));
				}
				else if (arg.StartsWith("/include:", StringComparison.InvariantCultureIgnoreCase))
				{
					include.AddRange(File.ReadAllLines(arg.Substring(9))
						.Select(i => i.Substring(0, i.IndexOf(':') > 0 ? i.IndexOf(" :") : i.Length).Trim())
						.Where(i => !String.IsNullOrWhiteSpace(i)));
				}
				else if (arg.StartsWith("/usecallback",StringComparison.InvariantCultureIgnoreCase))
                {
                    Options.Value.EnableOnBranchCallback = true;
                }
                else if(arg.StartsWith("/setversion:", StringComparison.InvariantCultureIgnoreCase))
                {
                    Options.Value.NewVersion = Int32.Parse(arg.Substring(12));
                }
                else if(arg.StartsWith("/print", StringComparison.InvariantCultureIgnoreCase))
                {
                    Options.Value.PrintInstrumentedTypes = true;
                }
			}

			var isCoreLib = files.Any(i=> Path.GetFileNameWithoutExtension(i) == "System.Private.CoreLib");
			if (isCoreLib && include.Count == 0)
			{
				Console.Error.WriteLine("At least one prefix is required when instrumenting System.Private.CoreLib.");
				return 1;
			}

			try
			{
				foreach (var file in files)
				{
					var types = Fuzzer.Instrument(file, Matcher, Options.Value);

					if (Options.Value.PrintInstrumentedTypes)
					{
						Console.WriteLine(file + ":");
						Console.WriteLine();
						foreach (var type in types)
						{
							Console.WriteLine(type);
						}
						Console.WriteLine();
					}
				}
			}
			catch (InstrumentationException ex)
			{
				Console.Error.WriteLine(ex.Message);
				return 1;
			}
			catch(Exception e)
			{
				Console.Error.WriteLine("Failed to instrument the specified file, most likely because it's not a valid .NET assembly.");
                Console.Error.WriteLine(e);
                return 1;
			}

			bool Matcher(string type)
			{
				var trimmed = type.Substring(type.IndexOf(' ') + 1);

				if (exclude.Any(prefix => trimmed.StartsWith(prefix, StringComparison.InvariantCultureIgnoreCase)))
				{
					Console.Error.WriteLine($"Excluded: {trimmed}");
					return false;
				}

				if (include.Count == 0)
				{
					return true;
				}

				if (include.Any(prefix => trimmed.StartsWith(prefix, StringComparison.InvariantCultureIgnoreCase)))
				{
					return true;
				}

				return false;
			}

			return 0;
		}
	}
}
