// TestHook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "..//HookHMVH/common.h"

typedef struct _HEAD
{
	HANDLE h;
	DWORD  cLockObj;
} HEAD, * PHEAD;

typedef struct _THROBJHEAD
{
	HEAD h;
	PVOID pti;
} THROBJHEAD, * PTHROBJHEAD;
//
typedef struct _THRDESKHEAD
{
	THROBJHEAD h;
	PVOID    rpdesk;
	PVOID       pSelf;   // points to the kernel mode address
} THRDESKHEAD, * PTHRDESKHEAD;


LRESULT CALLBACK MainWProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

int main()
{
	BOOL bFound = FindHMValidateHandle();
	LoadLibraryA("HookHMVH.dll");

	if (!bFound) {
		printf("[-] Failed to locate HmValidateHandle, exiting\n");
		return 1;
	}
	printf("[i] Found location of HMValidateHandle in user32.dll\n");
	WNDCLASSEX wnd = { 0x0 };
	wnd.cbSize = sizeof(wnd);
	wnd.lpszClassName = TEXT("MainWClass");
	wnd.lpfnWndProc = MainWProc;
	int result = RegisterClassEx(&wnd);
	if (!result)
	{
		printf("RegisterClassEx error: %d\r\n", GetLastError());
	}

	HWND test = CreateWindowEx(
		0,
		wnd.lpszClassName,
		TEXT("WORDS"),
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL, NULL, NULL, NULL);
	printf("[i] IsMenu being called\n");
	IsMenu((HMENU)test);
	printf("[i] IsMenu called\n");
	PTHRDESKHEAD tagWND = (PTHRDESKHEAD)pHmValidateHandle(test, 1);

#ifdef _WIN64
	printf("Kernel memory address: 0x%llx, tagTHREAD memory address: 0x%llx\n", tagWND->pSelf, tagWND->h.pti);
#else
	printf("Kernel memory address: 0x%X, tagTHREAD memory address: 0x%X\n", tagWND->pSelf, tagWND->h.pti);
#endif
	return 0;
}