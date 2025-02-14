using System;

namespace SharpFuzz
{
    /// <summary>
	/// Experimental options for controlling the instrumentation behavior.
	/// </summary>
	public sealed class Options
    {
        /// <summary>
        /// Values of all experimental instrumentation flags.
        /// </summary>
        public static readonly Options Value = new Options();

        private Options()
        {
            EnableOnBranchCallback = GetValue("SHARPFUZZ_ENABLE_ON_BRANCH_CALLBACK");
            AlterTraceCalc = GetValue("SHARPFUZZ_ALTER_TRACE_MODE");
            PrintInstrumentedTypes = GetValue("SHARPFUZZ_PRINT_INSTRUMENTED_TYPES");
            InstrumentMixedModeAssemblies = GetValue("SHARPFUZZ_INSTRUMENT_MIXED_MODE_ASSEMBLIES");
        }

        /// <summary>
        /// Enable calling user-specified callback at
        /// every instrumented branch. Example usage:
        /// 
        /// SharpFuzz.Common.Trace.OnBranch = (branchId, functionName) => {
        ///     do whatever you want here
        /// };
        /// </summary>
        public bool EnableOnBranchCallback { get; set; }

        /// <summary>
        /// Use alternative mode for footprints in coverage map
        /// </summary>
        public bool AlterTraceCalc { get; set; }

        /// <summary>
        /// Print the list of all instrumented types to standard console output.
        /// </summary>
        public bool PrintInstrumentedTypes { get; set; }

        /// <summary>
        /// Enable instrumenting mixed-mode assemblies (supported only on Windows).
        /// Used to instrument .NET Core system libraries.
        /// </summary>
        public bool InstrumentMixedModeAssemblies { get; set; }

        /// <summary>
        /// If not zero, defines major version of assembly
        /// </summary>
        public int NewVersion { get; set; }   

        private static bool GetValue(string flag)
        {
            return Environment.GetEnvironmentVariable(flag) is object;
        }
    }
}
