# PostDump

----

PostDump is a C# tool developt by COS team (Cyber Offensive and Security) of POST Luxembourg.

It is yet another simple tool to perform a memory dump (lsass) using several technics to bypass EDR hooking and lsass protection.

Unlike tools like EDRSandBlast, it focused on unhooking only functions stricly required in order to dump the memory, thus done by using DInvoke to map required unhooked DLL. With an exception for NtReadVirtualMemory which is dynamicly patched if hook is detected.

Project in constant improvement (hook detection, direct syscalls).

## Technics used

- DInvoke -> Credit to TheWover for its C# implementation [C# DInvoke](https://github.com/TheWover/DInvoke)
- PssCaptureSnapshot Duplicate Handle -> Credit to Inf0SecRabbit for its C# implementation [MiniDumpSnapshot](https://github.com/Inf0secRabbit/MiniDumpSnapshot)
- NtReadVirtualMemory hook patching (Patch instead of DInvoke call due to MiniDumpWriteDump "underthehood" call to NtReadVirtualMemory)
- MiniDumpWriteDump to dump memory


## Behavior

- Check if NtReadVirtualMemory is hooked, if yes -> patching
- Map NTDLL.dll from disk using DInvoke to call unhooked NtOpenProcess functions and get handle on LSASS process using only PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION privileges (minimum required for PssCaptureSnapshot)
- Map Kernel32.dll from disk using DInvoke to call unhooked PssCaptureSnapshot function and duplicate LSASS
- Map dbgcore.dll from disk using DInvoke to call unhooked MiniDumpWriteDump function and dump duplicated handle


## Usage

Dump LSASS:

    C:\Temp>PostDump.exe

    [*] NtReadVirtualMemory: HOOKED! Patching...
    [*] NtReadVirtualMemory --> NOT Hooked!
    
    [*] NtOpenProcess: NOT Hooked!
    [*] Real Process Handle: 728
    
    [*] PssCaptureSnapshot: NOT Hooked!
    [*] Snapshot succeed! Duplicate handle: 1549097566208
    
    [*] MiniDumpWriteDump: NOT Hooked!
    [*] Duplicate dump successful. Dumped 49737034 bytes to: c:\Temp\yolo.log


## Compile Instructions

PostDump has been built using .NET Framework 4.8 and is compatible with [Visual Studio 2022 Community Edition](https://visualstudio.microsoft.com/fr/thank-you-downloading-visual-studio/?sku=Community&channel=Release&version=VS2022&source=VSLandingPage&cid=2030&passive=false). 
Simply open up the project .sln, choose "release x64", and build.
