#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
//////////////////////////////////////////////////////////////////////////////////
//We need to start by getting undocumented functions 
//:57

//0x1 bytes (sizeof)
//https://www.vergiliusproject.com/kernels/x86/windows-8.1/rtm/_PS_PROTECTION

typedef struct _PS_PROTECTION //offset = 0x87a from EPROCESS according to vergiliusproject
//confirmed this in windbg with dt _eprocess ->
//   +0x87a Protection       : _PS_PROTECTION
{
	UCHAR Type : 3; //protected
	UCHAR Audit : 1; //audit / not protected
	UCHAR Signer : 4; //who signed the image
	//example: 0x00 = unprotected.
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_PROTECTION_INFO
{
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection; // previously defined struct
} PROCESS_PROTECTION_INFO, * PPROCESS_PROTECTION_INFO;



//////////////////////////////////////////////////////////////////////////////////

extern "C" { //run some C in cpp

	//Forward declare functions that allow us to call undcoumented funcitnos similar to what we'd do w pointers to functions in C.

	//The IoCreateDriver function is part of the ntoskrnl.exe (Windows NT Operating System Kernel) 
	//rather than a DLL. It is a kernel-mode function provided by the Windows kernel itself.

	//Make this IOCTL driver compatible w kdmapper.
	//Create a driver manually accepting a driver name and a driver entry point/init function.
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

	//read/write process memory from within a dirver.
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
}


void debug_printer(PCSTR text) {

#ifndef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif //debug

	//KdPrint(Ex) only prints in compiled debug mode jsyk.
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}


namespace driver {
	namespace codes {
		//IOCTL codes - drivers to communicate w/ usermode apps and vice versa. 
		//UserMode applications call DeviceIoControl to send a struct -> drivers.
		//Then we recieve the struct and do whatever we want with it.


		//Must be buffered IO so we can send buffers between kernel and userland.

		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //setup the driver

		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //read process mem

		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //write process mem.

		constexpr ULONG getProtection = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //write process mem.

		constexpr ULONG unprotect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //write process mem.

		constexpr ULONG protect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //write process mem.

	}

	struct Request {
		HANDLE hPID; //
		PVOID pTargetMemory; //victim process
		PVOID pBuffer;
		SIZE_T sSize;
		SIZE_T sReturn_size;
	};

	//3 functinos for uDriverOBject event handleing.

	NTSTATUS create(PDEVICE_OBJECT pDeviceObject, PIRP irp) { 		//irp is the packet that carries the data between ICTL devices.
		UNREFERENCED_PARAMETER(pDeviceObject);
		IoCompleteRequest(irp, IO_NO_INCREMENT); //every time we complete an IRP / complete incoming packet request, we must call this.
		return irp->IoStatus.Status; //OS/User can both see what status is when these handlers are called.
	}
	NTSTATUS close(PDEVICE_OBJECT pDeviceObject, PIRP irp) { 		//irp is the packet that carries the data between ICTL devices.
		UNREFERENCED_PARAMETER(pDeviceObject);
		IoCompleteRequest(irp, IO_NO_INCREMENT); //every time we complete an IRP / complete incoming packet request, we must call this.
		return irp->IoStatus.Status; //OS/User can both see what status is when these handlers are called.
	}

	//everytime we call DeviceIoControl (send stuff to kernel) this is called.  This is where read/write/attach comes in.
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

		static PEPROCESS target_process = nullptr; //this is static and survives after the fucntions been run so we can attach once, and use the same PEPROCESS object later.
		static PROCESS_PROTECTION_INFO* psProtection = nullptr;
		const ULONG control_code = stack_IRP->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code) {
		case codes::attach:
			status = PsLookupProcessByProcessId(request->hPID, &target_process);
			psProtection = (PROCESS_PROTECTION_INFO*)(((ULONG_PTR)target_process) + 0x87a);
			break;
		case codes::read:
			//we need to have a target process before we cna read proc mem
			if (target_process != nullptr) {
				status = MmCopyVirtualMemory(target_process, request->pTargetMemory, PsGetCurrentProcess(), request->pBuffer, //copy memory from target -> driver
					request->sSize, KernelMode, &request->sReturn_size);
			}
			else {
				debug_printer("No target_process pointer when calling read IOCTL...\n");
				break;
			}
			break;
		case codes::write:

			if (target_process != nullptr) {
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->pBuffer, target_process, request->pTargetMemory, //copy memory from target -> driver
					request->sSize, KernelMode, &request->sReturn_size);
			}
			break;
		case codes::getProtection:
			if (target_process != nullptr && psProtection != nullptr) {
				if (!psProtection) {
					debug_printer("Error retrieving protection from EPROCESS struct, check your offsets?\n");
				}
				debug_printer("Recieved protection level of target process through kernel land access to memory...\n");
			}
			break;
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

		case codes::protect:
			if (target_process != nullptr && psProtection != nullptr) {
				psProtection->Protection.Type = 1;
				status = STATUS_SUCCESS;
				debug_printer("Added protection levels back...\n");
			}
			break;

			//We will be accessing fields within the EPROCESS field of a process via offsets.  
			//PsLookupProcessByProcessId returns a base pointer to the EPROCESS struct of a given process.  Adding onto this
			//Can help us find the EPROC

		default:
			break;

		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(request);
		IoCompleteRequest(irp, IO_NO_INCREMENT); //every time we complete an IRP / complete incoming packet request, we must call this.
		//if theres a null ptr computer blue screens..
		return status; //OS/User can both see what status is when these handlers are called.
	}
}


NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	//Because kdmapper is trying to load our kernel without 'windows knowing' or through traditional means, we need IoCreateDriver because that creates the DriverObject and registry path for us, it makes everythign fall back into alignment w how things wouold be done traditionally.


	UNREFERENCED_PARAMETER(RegistryPath); //we're never going to use this and warnings dont let us compile drivers.

	//Create the drivers device.

	UNICODE_STRING uDeviceName = { };
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\noah"); //driver name always reamins the same.

	//now use string to create device obj

	PDEVICE_OBJECT pDeviceObject = nullptr;//populates w pointer after IoCreateDevice

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);


	if (status != STATUS_SUCCESS) {
		debug_printer("FAILED TO CREATE DRIVER DEVICE....\n");
		return status;
	}

	debug_printer("Driver device succesfully created...\n");

	//Sym link

	UNICODE_STRING uSymLink = {};
	RtlInitUnicodeString(&uSymLink, L"\\DosDevices\\noah"); //driver name always reamins the same.

	status = IoCreateSymbolicLink(&uSymLink, &uDeviceName);

	if (status != STATUS_SUCCESS) {
		debug_printer("FAILED TO CREATE SYBOLIC LINK....\n");
		return status;
	}

	debug_printer("Driver sym link established...\n");

	//IOCTL comms.

	//Allows us to send small amounts of data between um/km
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

//inputs are from microsoft docs for DriverEntry()

//kdmapper calls DriverEntry
NTSTATUS DriverEntry() {
	//Drivers dont like const char* , they like UNICODE_STRING.  Use this method to initialize.
	UNICODE_STRING uDriverName = {};

	//Name must be \\Driver\\<WHATEVER>
	RtlInitUnicodeString(&uDriverName, L"\\Driver\\noah");


	return IoCreateDriver(&uDriverName, DriverMain); //We call create driver which is
}