#include <Windows.h>
#include <cstdio>
#include <TlHelp32.h>

bool IsSpotifyProcess(const DWORD &dwProcessID)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!hSnapshot)
	{
		printf("CreateToolhelp32Snapshot failed with error: %d\n", GetLastError());
		return false;
	}

	PROCESSENTRY32 p32{ };
	p32.dwSize = sizeof PROCESSENTRY32;

	if( !Process32FirstW(hSnapshot, &p32) )
	{
		CloseHandle(hSnapshot);
		printf("Process32FirstW failed with error: %d\n", GetLastError());
		return false;
	}

	auto res = false;
	do
	{
		if (!_wcsicmp(p32.szExeFile, L"Spotify.exe") && dwProcessID == p32.th32ProcessID)
		{
			res = true;
			break;
		}

	} while (Process32NextW(hSnapshot, &p32));

	CloseHandle(hSnapshot);
	return res;
}

inline void Injection()
{
	wchar_t wsFileBuffer[MAX_PATH];
	GetFullPathNameW(L".\\Spotify AdsRemover.dll", MAX_PATH, wsFileBuffer, nullptr);

	if (GetFileAttributesW(wsFileBuffer) == INVALID_FILE_ATTRIBUTES)
	{
		printf("DLL file has not been found!\n");
		return;
	}

	auto Window = FindWindowW(L"Chrome_WidgetWin_0", NULL);

	if (!Window)
	{
		printf("Failed to find Spotify window!\n");
		return;
	}

	DWORD dwProcID = NULL;
	GetWindowThreadProcessId(Window, &dwProcID);

	if (!IsSpotifyProcess(dwProcID))
	{
		printf("Found window ( %d ) is not a Spotify process!\n", dwProcID);
		return;
	}

	const auto DllLen = wcslen(wsFileBuffer) * sizeof WCHAR;

	auto Process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, dwProcID);

	if( !Process )
	{
		printf("OpenProcess failed with error: %d!\n", GetLastError());
		return;
	}

	auto DllLocation = VirtualAllocEx(Process, nullptr, DllLen + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if( !DllLocation )
	{
		printf("VirtualAllocEx failed with error: %d!\n", GetLastError());
		return;
	}

	if (!WriteProcessMemory(Process, DllLocation, wsFileBuffer, DllLen, nullptr))
	{
		printf("WriteProcessMemory failed with error: %d!\n", GetLastError());
		return;
	}

	auto fnLoadLibraryW = PBYTE(&LoadLibraryW);

	auto Thread = CreateRemoteThread(Process, nullptr, NULL, (LPTHREAD_START_ROUTINE)fnLoadLibraryW, DllLocation, NULL, NULL);
	if( !Thread )
	{
		printf("CreateRemoteThread failed with error: %d!\n", GetLastError());
		return;
	}

#ifdef _DEBUG
	printf("Thread->%p\n", Thread);
	printf("Process->%p\n", Process);
	printf("DllLocation->%p\n", DllLocation);
#endif

	WaitForSingleObject(Thread, 10 * 1000);

	DWORD dwExitCode = NULL;
	if (GetExitCodeThread(Thread, &dwExitCode))
	{
		if (dwExitCode > 0)
			printf("Injected successfully!\n");
	}
	
	if(dwExitCode <= 0)
		printf("Injection failed, thread returned: %X\n", dwExitCode);
}

int main()
{
	SetConsoleTitleW(L"Spotify AdsRemover v1");

	Injection();
	
	Sleep(6500);

	return 0;
}