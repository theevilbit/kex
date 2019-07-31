// dllmain.cpp : Defines the entry point for the DLL application.
#pragma comment(lib, "detours.lib")

#include "common.h"
#include <detours.h>

#define _CRT_SECURE_NO_WARNINGS 1
#define STACK_ENTRIES 2 //number of stack entries to read in the hook

//variables to store the user32.dll address range of the code segment
SIZE_T user32_dll_start = 0;
SIZE_T user32_dll_end = 0;

//this will calculate the code segment of the user32.dll
//https://stackoverflow.com/questions/17892829/how-to-find-the-in-memory-address-of-a-specific-instruction-in-a-dll
BOOL CalculateDllMemoryRange()
{
	HMODULE dllHandle;
	FILE* dllFile;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	IMAGE_SECTION_HEADER sectionHeader;

	unsigned int i;
	unsigned char* starAddr;
	unsigned char* endAddr;

	if ((dllFile = fopen("c:\\windows\\system32\\user32.dll", "rb")) == NULL) {
		printf("[-] Error opening file\n");
		return false;
	}

	// Read the basic PE headers
	fread(&dosHeader, sizeof(dosHeader), 1, dllFile);
	fseek(dllFile, dosHeader.e_lfanew, SEEK_SET);
	fread(&NtHeaders, sizeof(NtHeaders), 1, dllFile);

	// Search for the executable section, .text section.
	for (i = 0; i < NtHeaders.FileHeader.NumberOfSections; i++) {
		fread(&sectionHeader, sizeof(sectionHeader), 1, dllFile);
		// If we found a section that contains executable code,
		// we found our code setion.
		if ((sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
			printf("[*] Code section: `%s'\n", sectionHeader.Name);
			break;
		}
	}

	fclose(dllFile);

	// Load the DLL to get it's base address
	if ((dllHandle = GetModuleHandleA("user32.dll")) == NULL) {
		printf("[!] Error: loading the DLL, 0x%.8x\n", (unsigned int)GetLastError());
		return false;
	}

	// The code start at : base address + code virtual address
	starAddr = (unsigned char*)dllHandle + sectionHeader.VirtualAddress;
	// It ends at : base address + code virtual address + virtual size
	endAddr = (unsigned char*)starAddr + sectionHeader.Misc.VirtualSize;

	printf("[*] Base address : 0x%Ix\n", (SIZE_T)dllHandle);
	printf("[*] Start address: 0x%Ix\n", (SIZE_T)starAddr);
	printf("[*] End address  : 0x%Ix\n", (SIZE_T)endAddr);

	user32_dll_start = (SIZE_T)starAddr;
	user32_dll_end = (SIZE_T)endAddr;

	return true;
}


// Detour function that replaces the HMValidateHandle API.
//
#ifdef _WIN64
VOID* WINAPI ProtectHMValidateHandle(HWND h, int type)
#else
PVOID __fastcall ProtectHMValidateHandle(HWND h, int type)
#endif
{
	printf("[*] Hooked function called\n");
	void* stack[STACK_ENTRIES] = { 0 }; 
	WORD numberOfFrames = CaptureStackBackTrace(0, STACK_ENTRIES, stack, NULL);
	for (USHORT iFrame = 0; iFrame < numberOfFrames; ++iFrame) {
		printf("[%3d] = %p\n", iFrame, stack[iFrame]);
	}
	
	//the 1st item on the stack is the hook, the 2nd item is the original caller, which should be always originate from user32.dll as the function is not exported
	//verify if the call origin is inside the user32.dll code segment
	if ((SIZE_T)stack[1] < user32_dll_start || (SIZE_T)stack[1] > user32_dll_end)
	{
		printf("[\\o/] Exploit detected, exiting program...\n");
		ExitProcess(-1);
	}
	//call the original function
	return pHmValidateHandle(h, type);
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		if (CalculateDllMemoryRange()) //only hook if we can calculate the user32.dll address range
		{
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			BOOL bFound = FindHMValidateHandle();
			if (!bFound) {
				printf("[-] Failed to locate HmValidateHandle, exiting\n");
				return TRUE;
			}
			printf("[+] Found location of HMValidateHandle in user32.dll\n");
			printf("[i] HMValidateHandle address: 0x%Ix\n", (SIZE_T)(pHmValidateHandle));
			DetourAttach(&(PVOID&)pHmValidateHandle, ProtectHMValidateHandle);
			DetourTransactionCommit();
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		if (user32_dll_start != 0) //we could calculate the user32.dll addresses previously
		{
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			if (pHmValidateHandle != nullptr) //we could calculate the HMValidateHandle address previously
			{
				DetourDetach(&(PVOID&)pHmValidateHandle, ProtectHMValidateHandle);
			}
			DetourTransactionCommit();
		}
	}
	return TRUE;
}