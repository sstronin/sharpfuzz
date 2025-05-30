﻿using System;
using System.Runtime.InteropServices;

namespace SharpFuzz.Common
{
	/// <summary>
	/// Trace contains instrumentation injected into fuzzed programs.
	/// This is internal implementation class not meant for public use.
	/// </summary>
	public static unsafe class Trace
	{
		/// <summary>
		/// Instrumentation bitmap. Contains XORed pairs of data: identifiers of the
		/// currently executing branch and the one that executed immediately before.
		/// </summary>
		public volatile static byte* SharedMem;

		/// <summary>
		/// Identifier of the last executed branch.
		/// </summary>
		public volatile static int PrevLocation;

		/// <summary>
		/// Callback that will be called with the unique branch identifier
		/// and the current function name each time some branch is hit. It's
		/// disabled by default due to performance reasons, and will only be
		/// called if the user chose to use it when instrumenting the assembly.
		/// </summary>
		public volatile static Action<int, string> OnBranch;

        /// <summary>
        /// Alternative trace footprints mode
        /// </summary>
        public static bool AlterTraceMode;

        // default buffers to prevent crashing before test environment could be set
        static Trace()
        {
            var intPtr = Marshal.AllocHGlobal(0x10000);
            SharedMem = (byte*)intPtr.ToPointer();
            PrevLocation = 0;
        }

        public static void OnBranchCall(int branchId, string branchName)
        {
            if(SharedMem!=null)
            {
                SharedMem[branchId ^ PrevLocation] += 1;
                PrevLocation = branchId / 2;
            }
            if (OnBranch != null)
            {
                OnBranch.Invoke(branchId, branchName);
            }
        }

        public static void OnBranchAlter(int branchId, string branchName)
        {
            if (SharedMem != null)
            {
                SharedMem[(branchId ^ PrevLocation) >> 4] |= 
                    (byte)(1 << ((branchId ^ PrevLocation) & 0x7));
                PrevLocation = branchId / 2;
            }
            if (OnBranch != null)
            {
                OnBranch.Invoke(branchId, branchName);
            }
        }
    }
}
