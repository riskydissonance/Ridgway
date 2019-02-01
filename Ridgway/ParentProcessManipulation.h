#pragma once
#include "Ridgway.h"
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

		PLUID_AND_ATTRIBUTES runner;
		bool seDebugAvailable = false;
		// Iterate over the privs and check for the debug priv LUID
		for (DWORD x = 0; x < processTokenPrivs->PrivilegeCount; x++) {
			runner = &processTokenPrivs->Privileges[x];
			if ((runner->Luid.LowPart == privilegeLuid.LowPart) && (runner->Luid.HighPart == privilegeLuid.HighPart)) {
				_tprintf(_T("[+] SeDebugPrivilege available!\n"));
				seDebugAvailable = true;
				break;
			}
		}

		if (!seDebugAvailable) {
			_tprintf(_T("[-] SeDebugPrivilege unavailable\n[-] Please run with Privileges!\n"));
			CloseHandle(currentTokenHandle);
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
	HANDLE parentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId);
	// TODO check if process is for current user and if not ask for debug priv
	if (nullptr == parentProcessHandle)
	{
		_tprintf(TEXT("[*] Could not get handle, trying to get debug privilege to retry...\n"));
		if (!GetDebugPrivilege())
		{
			return nullptr;
		}
		parentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId);
	}
	return parentProcessHandle;
}

PPROC_THREAD_ATTRIBUTE_LIST GetParentAttributeList(HANDLE &parentProcessHandle)
{
	SIZE_T attributeListSize = 0;
	// Pass null to get the size of the attribute list
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);

	// Allocate space for it
	PPROC_THREAD_ATTRIBUTE_LIST parentAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeListSize);
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
	return parentAttributeList;
}

PROCESS_INFORMATION StartProcessSuspended(_TCHAR* processName, int parentProcessId)
{

	PROCESS_INFORMATION processInfo;
	if (parentProcessId == 0)
	{
		_putts(TEXT("Invalid pid"));
		return processInfo;
	}

	// Get a handle on the parent process
	HANDLE parentProcessHandle = GetParentProcessHandle(parentProcessId);

	if (nullptr == parentProcessHandle) { return processInfo; }

	STARTUPINFOEX startupInfo = { sizeof(startupInfo) };

	// Get the attribute list from the parent process
	PPROC_THREAD_ATTRIBUTE_LIST parentAttributeList = GetParentAttributeList(parentProcessHandle);

	if (parentAttributeList == nullptr)
	{
		DisplayErrorMessage(TEXT("Error getting attributes from parent process"), GetLastError());
		return processInfo;
	}

	// Set the startup info attribute list to the one set from the 'parent'.
	startupInfo.lpAttributeList = parentAttributeList;

	// Create the process
	if (!CreateProcess(nullptr, processName, nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr, &startupInfo.StartupInfo, &processInfo))
	{
		DisplayErrorMessage(TEXT("CreateProcess error"), GetLastError());
		return processInfo;
	}
	_tprintf(TEXT("[+] Process created: %d\n"), processInfo.dwProcessId);

	// Cleanup
	DeleteProcThreadAttributeList(parentAttributeList);
	CloseHandle(parentProcessHandle);
	return processInfo;
}