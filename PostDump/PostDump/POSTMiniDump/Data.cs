using System;
using System.Runtime.InteropServices;

namespace POSTMiniDump
{
    public class Data
    {
        public const ulong DUMP_MAX_SIZE = 0x0c800000;
        public const ulong SIZE_OF_HEADER = 32;
        public const ulong SIZE_OF_DIRECTORY = 12;
        public const uint PROCESS_PARAMETERS_OFFSET = 0x20;
        public const uint OSMAJORVERSION_OFFSET = 0x118;
        public const uint OSMINORVERSION_OFFSET = 0x11c;
        public const uint OSBUILDNUMBER_OFFSET = 0x120;
        public const uint OSPLATFORMID_OFFSET = 0x124;
        public const ulong SIZE_OF_SYSTEM_INFO_STREAM = 48;
        public const ulong SIZE_OF_MINIDUMP_MODULE = 108;
        public const uint CSDVERSION_OFFSET = 0x2e8;
        public const uint PEB_OFFSET = 0x60;
        public const uint MINIDUMP_SIGNATURE = 0x504d444d;
        public const uint MINIDUMP_VERSION = 42899;
        public const ushort MINIDUMP_IMPL_VERSION = 0;
        public const uint LDR_POINTER_OFFSET = 0x18;
        public const uint MODULE_LIST_POINTER_OFFSET = 0x20;
        public const int MAX_PATH = 260;


        public class dump_context
        {
            public IntPtr hProcess;
            public IntPtr BaseAddress;
            public long rva;
            public ulong DumpMaxSize;
            public uint Signature;
            public uint Version;
            public ushort ImplementationVersion;
        }

        public class MiniDumpMemoryDescriptor64
        {
            public MiniDumpMemoryDescriptor64 next;
            public IntPtr StartOfMemoryRange;
            public ulong DataSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;

            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(MiniDumpMemoryDescriptor64)); }
            }
        }

        public class PModuleInfo
        {
            public MODULEINFO moduleinfo;
            public Data.UNICODE_STRING dll_name;
            public long name_rva;
            public ulong TimeDateStamp;
            public uint CheckSum;
        }

        public class MiniDumpModule
        {
            public IntPtr BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public ulong TimeDateStamp;
            public IntPtr ModuleNameRva;
            public VsFixedFileInfo VersionInfo;
            public MiniDumpLocationDescriptor CvRecord;
            public MiniDumpLocationDescriptor MiscRecord;
            public ulong Reserved0;
            public ulong Reserved1;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct OsVersionInfo
        {
            public readonly uint OsVersionInfoSize;

            public readonly uint MajorVersion;
            public readonly uint MinorVersion;

            public readonly uint BuildNumber;

            public readonly uint PlatformId;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public readonly string CSDVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MiniDumpHeader
        {
            public uint Signature;
            public uint Version;
            public ushort ImplementationVersion;
            public uint NumberOfStreams;
            public ulong StreamDirectoryRva;
            public uint CheckSum;
            public uint Reserved;
            public ulong TimeDateStamp;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MiniDumpDirectory
        {
            public uint StreamType;
            public uint DataSize;
            public long Rva;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MiniDumpSystemInfo
        {
            public Data.ProcessorArchitecture ProcessorArchitecture;
            public short ProcessorLevel;
            public short ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public ulong CSDVersionRva;
            public short SuiteMask;
            public short Reserved2;
            public ulong ProcessorFeatures1;
            public ulong ProcessorFeatures2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MiniDumpLocationDescriptor
        {
            public uint DataSize;
            public long rva;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct VsFixedFileInfo
        {
            public uint dwSignature;
            public uint dwStrucVersion;
            public uint dwFileVersionMS;
            public uint dwFileVersionLS;
            public uint dwProductVersionMS;
            public uint dwProductVersionLS;
            public uint dwFileFlagsMask;
            public uint dwFileFlags;
            public uint dwFileOS;
            public uint dwFileType;
            public uint dwFileSubtype;
            public uint dwFileDateMS;
            public uint dwFileDateLS;
        }

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [Flags]
        public enum FileAccess : uint
        {
            ReadControl = 0x20000,
            Synchronize = 0x100000,
            StandardRightsWrite = ReadControl,

            FILE_WRITE_DATA = 0x0002,
            FILE_APPEND_DATA = 0x0004,
            FILE_WRITE_EA = 0x0010,
            FILE_WRITE_ATTRIBUTES = 0x0100,

            FILE_GENERIC_WRITE = StandardRightsWrite |
                FILE_WRITE_DATA |
                FILE_WRITE_ATTRIBUTES |
                FILE_WRITE_EA |
                FILE_APPEND_DATA |
                Synchronize,
        }

        public enum ProcessorArchitecture
        {
            AMD64 = 9,
            INTEL = 0,
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public ulong RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        public enum MEMORY_INFORMATION_CLASS
        {
            MemoryBasicInformation
        }

        public enum PROCESSINFOCLASS
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;
            public int Size
            {
                get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }


        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;

        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;

        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING([MarshalAs(UnmanagedType.LPWStr)]  string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(Buffer);
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public long QuadPart;

            [FieldOffset(0)] public uint LowPart;
            [FieldOffset(4)] public int HighPart;

            [FieldOffset(0)] public int LowPartAsInt;
            [FieldOffset(0)] public uint LowPartAsUInt;

            [FieldOffset(4)] public int HighPartAsInt;
            [FieldOffset(4)] public uint HighPartAsUInt;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ACTIVATION_CONTEXT
        {
            public int cbSize;
            public uint dwFlags;
            public Data.UNICODE_STRING lpSource;
            public UInt16 wProcessorArchitecture;
            public UInt16 wLangId;
            public Data.UNICODE_STRING lpAssemblyDirectory;
            public IntPtr lpResourceName;
            public Data.UNICODE_STRING lpApplicationName;
            public IntPtr hModule;
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_IMPORT_DESCRIPTOR
        {
            [FieldOffset(0)]
            public uint Characteristics;

            [FieldOffset(0)]
            public uint OriginalFirstThunk;

            [FieldOffset(4)]
            public uint TimeDateStamp;

            [FieldOffset(8)]
            public uint ForwarderChain;

            [FieldOffset(12)]
            public uint Name;

            [FieldOffset(16)]
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public unsafe struct LDRP_LOAD_CONTEXT
        {
            public UNICODE_STRING BaseDllName;
            public void* somestruct;
            public uint Flags;
            public NTSTATUS* pstatus;
            public LDR_DATA_TABLE_ENTRY* ParentEntry; 
            public LDR_DATA_TABLE_ENTRY* Entry; 
            public LIST_ENTRY WorkQueueListEntry;
            public LDR_DATA_TABLE_ENTRY* ReplacedEntry;
            public LDR_DATA_TABLE_ENTRY** pvImports;
            public uint ImportDllCount;
            public int TaskCount;
            public void* pvIAT;
            public uint SizeOfIAT;
            public uint CurrentDll;
            public IMAGE_IMPORT_DESCRIPTOR piid;
            public uint OriginalIATProtect;
            public void* GuardCFCheckFunctionPointer;
            public void* pGuardCFCheckFunctionPointer;
        };
        
        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }
        
        public unsafe struct LDR_SERVICE_TAG_RECORD
        {
            public LDR_SERVICE_TAG_RECORD* Next;
            public uint ServiceTag; 
        }

        public unsafe struct SINGLE_LIST_ENTRY
        {
            public SINGLE_LIST_ENTRY* Next;
        }

        public unsafe struct LDRP_CSLIST
        {
            public SINGLE_LIST_ENTRY* Tail;
        }


        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct LDR_DDAG_NODE
        {
            [FieldOffset(0x00)]
            public LIST_ENTRY Modules;

            [FieldOffset(0x8)]
            public LDR_SERVICE_TAG_RECORD* ServiceTagList;

            [FieldOffset(0xc)]
            public uint LoadCount;

            [FieldOffset(0x10)]
            public uint ReferenceCount;

            [FieldOffset(0x14)]
            public uint DependencyCount;

            [FieldOffset(0x18)]
            public LDRP_CSLIST Dependencies;

            [FieldOffset(0x18)]
            public SINGLE_LIST_ENTRY RemovalLink;

            [FieldOffset(0x1c)]
            public LDRP_CSLIST IncomingDependencies;

            [FieldOffset(0x20)]
            public LDR_DDAG_STATE State;

            [FieldOffset(0x24)]
            public SINGLE_LIST_ENTRY CondenseLink;

            [FieldOffset(0x28)]
            public uint PreorderNumber;

            [FieldOffset(0x2c)]
            public uint LowestLink;
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct RTL_BALANCED_NODE
        {
            [FieldOffset(0x00)]
            public RTL_BALANCED_NODE* Children;

            [FieldOffset(0x00)]
            public RTL_BALANCED_NODE* left;

            [FieldOffset(0x08)]
            public RTL_BALANCED_NODE* Right;

            [FieldOffset(0x10)]
            public char Red;

            [FieldOffset(0x10)]
            public char Balance;

            [FieldOffset(0x10)]
            public ulong ParentValue;
        }
       
        public unsafe struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderList;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
            public fixed char Flags[2];
            public short ObsoleteLoadCount;
            public short TlsIndex;
            public LIST_ENTRY HashLinks;
            public uint TimeDateStamp;
            private uint Reserved;
            public ACTIVATION_CONTEXT* EntryPointActivationContext;
            public IntPtr Lock;
            public LDR_DDAG_NODE* DdagNode;
            public LIST_ENTRY NodeModuleLink;
            public LDRP_LOAD_CONTEXT* LoadContext;
            public IntPtr ParentDllBase;
            public IntPtr SwitchBackContext;
            public RTL_BALANCED_NODE BaseAddressIndexNode;
            public RTL_BALANCED_NODE MappingInfoIndexNode;
            public ulong OriginalBase;
            public LARGE_INTEGER LoadTime;
            public uint BaseNameHashValue;
            public uint LoadReason;
            public uint ImplicitPathOptions;
            public uint ReferenceCount;
            public uint DependentLoadFlags;
            public char SigningLevel;
            public uint CheckSum;
        }
        
        public enum LDR_DDAG_STATE : int
        {
            LdrModulesMerged = -5,
            LdrModulesInitError = -4,
            LdrModulesSnapError = -3,
            LdrModulesUnloaded = -2,
            LdrModulesUnloading = -1,
            LdrModulesPlaceHolder = 0,
            LdrModulesMapping = 1,
            LdrModulesMapped = 2,
            LdrModulesWaitingForDependencies = 3,
            LdrModulesSnapping = 4,
            LdrModulesSnapped = 5,
            LdrModulesCondensed = 6,
            LdrModulesReadyToInit = 7,
            LdrModulesInitializing = 8,
            LdrModulesReadyToRun = 9
        }

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InsufficientResources = 0xc000009a,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            ProcessIsTerminating = 0xc000010a,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            InvalidAddress = 0xc0000141,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }
    }
}
