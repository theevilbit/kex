#pragma once

#include <windows.h>
#include <stdio.h>

//HMValidateHandle definition
#ifdef _WIN64
typedef void* (NTAPI* lHMValidateHandle)(HWND h, int type);
#else
typedef void* (__fastcall* lHMValidateHandle)(HWND h, int type);
#endif

lHMValidateHandle pHmValidateHandle = NULL;

BOOL FindHMValidateHandle() {
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		printf("Failed to load user32");
		return FALSE;
	}

	BYTE* pIsMenu = (BYTE*)GetProcAddress(hUser32, "IsMenu");
	if (pIsMenu == NULL) {
		printf("Failed to find location of exported function 'IsMenu' within user32.dll\n");
		return FALSE;
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xE8) {
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {
		printf("Failed to find offset of HMValidateHandle from location of 'IsMenu'\n");
		return FALSE;
	}

	unsigned int addr = *(unsigned int*)(pIsMenu + uiHMValidateHandleOffset);
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr;
#ifdef _WIN64
	//The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11);
#else
	//this was adjusted for Windows 7 x86
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 15);
#endif
	return TRUE;
}