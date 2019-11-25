#include "stdafx.h"

constexpr static auto Ads1 = 0x00646100; //'ad'
constexpr static auto Ads2 = 0x2F736461; //'ads'

#define Caption			L"Spotify AdsRemover v1"

inline bool PatchAds()
{
	PBYTE BaseAddress = PBYTE(GetModuleHandleW(NULL));

	if (!BaseAddress)
	{
		MessageBoxW(GetForegroundWindow(), L"BaseAddress is null", Caption, MB_ICONERROR);
		return false;
	}

	PIMAGE_DOS_HEADER DosHeader = PIMAGE_DOS_HEADER(BaseAddress);
	PIMAGE_NT_HEADERS NtHeaders = PIMAGE_NT_HEADERS(BaseAddress + DosHeader->e_lfanew);

	if (NtHeaders->OptionalHeader.SizeOfHeaders <= 0)
	{
		MessageBoxW(GetForegroundWindow(), L"SizeOfHeaders is null", Caption, MB_ICONERROR);
		return false;
	}

	const auto ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
	bool res = false;

	//I think we dont should care about the pages protection, it looks RWE everytime.
	if (ImageSize >= sizeof DWORD)
	{
		for (auto i = 0ul; i <= ImageSize - sizeof(DWORD); ++i)
		{
			if (*(DWORD*)(BaseAddress + i) == Ads1)
			{
				res = true;
				*(DWORD*)(BaseAddress + i) = 0x00696900;
			}
			
			if (*(DWORD*)(BaseAddress + i) == Ads1)
			{
				res = true;
				*(DWORD*)(BaseAddress + i) = 0x2F736969;
			}
		}
	}

	if (res)
		MessageBoxW(GetForegroundWindow(), L"Ads patched successfully!", Caption, MB_ICONINFORMATION);
	else
		MessageBoxW(GetForegroundWindow(), L"Failed to patch ads!", Caption, MB_ICONERROR);

	return res;
}

extern "C" BOOL WINAPI EntryPoint(HMODULE hModule, DWORD dwReason, LPVOID)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)PatchAds, 0, 0, 0);
		break;
	}
	return true;
}

