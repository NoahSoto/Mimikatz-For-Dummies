#include <iostream>
#include <windows.h>
#include <winternl.h>

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
}



//Function definition for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);


const wchar_t* wProc = L"Notepad.exe";


int main(int argc, wchar_t* argv[]) {

	fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll"); //i know these strings r baddddd
	if (!hNtdll) {
		printf("Failure finding module...");
		return 0;
	}
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation"); //i should probabyl do some kind fo encoding for this..

	if (!pNtQuerySystemInformation) {
		printf("Failure finding fucntion...");
		return 0;
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

	HANDLE hTarget = NULL;
	while (true) {
		if (pSystemProcessInformation->ImageName.Length && wcscmp(pSystemProcessInformation->ImageName.Buffer, wProc) == 0) { //make sure the process ahs a name 
			// openning a handle to the target process and saving it, then breaking 
			wprintf(L"[i] Process \"%s\" - Of Pid : %d \n", pSystemProcessInformation->ImageName.Buffer, pSystemProcessInformation->UniqueProcessId);
			hTarget = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pSystemProcessInformation->UniqueProcessId);
			break;
		}

		if (!pSystemProcessInformation->NextEntryOffset) {
			printf("Broken?");
			break;
		}
		// moving to the next element in the array
		pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
	}


	//Driver stuf...

	const HANDLE hDriver = CreateFile(L"\\\\.\\noah", GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);

	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("ERROR W DRIVER HANDLE");
		return 1;
	}

	if (driver::attachToProcess((DWORD)pSystemProcessInformation->UniqueProcessId, hDriver) == true) {
		printf("Attached!\n");
	}
	

	std::cout << "Hello world\n";

	return 0;
}