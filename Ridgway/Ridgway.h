#pragma once

void DisplayErrorMessage(LPTSTR pszMessage, DWORD dwLastError)
{
	HLOCAL hlErrorMessage = nullptr;
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, nullptr, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR)&hlErrorMessage, 0, nullptr))
	{
		_tprintf(TEXT("[-] %s: %s\n"), pszMessage, (PCTSTR)LocalLock(hlErrorMessage));
		LocalFree(hlErrorMessage);
	}
}

template<typename... Args>
void DebugPrint(LPTSTR message, Args... args)
{
#ifdef DEBUG
	_tprintf(message, args...);
#endif
}