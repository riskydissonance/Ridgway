#pragma once
#include<shellapi.h>
#include<winnt.h>

#define	MAXFILEPATHLEN	5000

void RelaunchSelf(void) {

	DebugPrint(TEXT("[*] Relaunching using runas.exe to escalate privileges\n"));
	SHELLEXECUTEINFO info;
	WCHAR fileName[MAXFILEPATHLEN];
	DWORD pathLen = MAXFILEPATHLEN;

	GetModuleFileName(nullptr, fileName, pathLen);

	info.cbSize = sizeof(SHELLEXECUTEINFO);
	info.fMask = SEE_MASK_DEFAULT;
	info.hwnd = nullptr;
	info.lpVerb = _T("runas");
	info.lpFile = fileName;
	info.lpParameters = nullptr;
	info.lpDirectory = nullptr;
	info.nShow = SW_SHOWNORMAL;

	ShellExecuteEx(&info);

}