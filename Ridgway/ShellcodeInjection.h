#pragma once
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include "Internals.h"

char shellcode[] = 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xcc\x91\x91\x91\x91";


/*BOOL InjectShellcodeOld(PROCESS_INFORMATION processInfo)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");
	if (!hNTDLL)
		return FALSE;
	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hNTDLL,
		"NtQueryInformationProcess"
	);
	if (!fpNtQueryInformationProcess)
		return 0;
	_NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION* processBasicInfo =
		new PROCESS_BASIC_INFORMATION();
	DWORD returnLength;
	ntQueryInformationProcess(processInfo.hProcess, 0, processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	
/*	if (!ntQueryInformationProcess(processInfo.hProcess, 0, processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnLength))
	{
		DisplayErrorMessage(TEXT("Error querying process information"), GetLastError());
		getchar();
		return FALSE;
	}
	* 
	_tprintf(TEXT("Attach debugger..."));
	getchar();
	PVOID pRemoteImage = VirtualAllocEx
	(
		processInfo.hProcess,
		(LPVOID) processBasicInfo->PebBaseAddress,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteImage)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory
	(
		processInfo.hProcess,
		(LPVOID) processBasicInfo->PebBaseAddress,
		shellcode,
		sizeof(shellcode),
		0
	))
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		return FALSE;
	}

	return TRUE;
} */


HMODULE GetRemoteModuleHandle(DWORD lpProcessId, LPCSTR lpModule)
{
	HMODULE hResult = NULL;
	HANDLE hSnapshot;
	MODULEENTRY32 me32;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lpProcessId);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				char * szModule;
				wcstombs(szModule, me32.szModule, sizeof(me32.szModule));
				if (!stricmp(szModule, lpModule))
				{
					hResult = me32.hModule;
					break;
				}
			} while (Module32Next(hSnapshot, &me32));
		}
		CloseHandle(hSnapshot);
	}
	return hResult;
}

/*BOOL InjectShellcode(PROCESS_INFORMATION processInfo)
{
	MODULEINFO moduleInfo;
	//if (!GetModuleInformation(processInfo.hProcess, NULL, moduleInfo, sizeof(moduleInfo))) 
	//{
	//	DisplayErrorMessage(TEXT("Error querying process information"), GetLastError());
	//	return FALSE;
	//}
	HMODULE hModule = GetRemoteModuleHandle(processInfo.dwProcessId, "notepad.exe");
	GetModuleInformation(processInfo.hProcess, hModule, &moduleInfo, sizeof(moduleInfo));

	/*	if (!ntQueryInformationProcess(processInfo.hProcess, 0, processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnLength))
		{
			DisplayErrorMessage(TEXT("Error querying process information"), GetLastError());
			getchar();
			return FALSE;
		}
		* /
	_tprintf(TEXT("Attach debugger..."));
	getchar();
	PVOID pRemoteImage = VirtualAllocEx
	(
		processInfo.hProcess,
		moduleInfo.EntryPoint,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!pRemoteImage)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory
	(
		processInfo.hProcess,
		moduleInfo.EntryPoint,
		shellcode,
		sizeof(shellcode),
		0
	))
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		return FALSE;
	}

	return TRUE;
}*/

BOOL InjectShellcode(PROCESS_INFORMATION processInfo)
{
	MODULEINFO moduleInfo;
	_tprintf(TEXT("Attach debugger..."));
	getchar();
	// Resume execution
	if (!ResumeThread(processInfo.hThread))
	{
		DisplayErrorMessage(TEXT("Error resuming thread"), GetLastError());
		getchar();
		return FALSE;
	}
	PVOID mem = VirtualAllocEx
	(
		processInfo.hProcess,
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!mem)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(processInfo.hProcess, mem, shellcode, sizeof(shellcode), NULL)) 
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		getchar();
		return FALSE;
	}

	if(!CreateRemoteThread(processInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) mem, NULL, PAGE_EXECUTE_READWRITE, NULL))
	{
		DisplayErrorMessage(TEXT("Error creating thread"), GetLastError());
		getchar();
		return FALSE;
	}
	getchar();
	return TRUE;
}


