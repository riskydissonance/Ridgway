#pragma once

void DisplayErrorMessage(LPTSTR pszMessage, DWORD dwLastError)
{
	HLOCAL hlErrorMessage = NULL;
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR)&hlErrorMessage, 0, NULL))
	{
		_tprintf(TEXT("[-] %s: %s"), pszMessage, (PCTSTR)LocalLock(hlErrorMessage));
		LocalFree(hlErrorMessage);
	}
}