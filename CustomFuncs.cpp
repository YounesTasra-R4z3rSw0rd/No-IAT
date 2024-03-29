#include "PEstructs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "CustomFuncs.h"

typedef HMODULE (WINAPI * LoadLibraryA_DT)(LPCSTR lpLibFileName);
LoadLibraryA_DT pLoadLibraryA = NULL;

HMODULE WINAPI CustomGetModuleHandle(LPCWSTR sModuleName) {

    /*------[GET OFFSET OF PEB]------*/
#ifdef _M_IX86
    PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
    PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

    /*------[RET BASE ADDRESS OF CALLING MODULE IF NO MODULE WAS PROVIDED]------*/
    if (sModuleName == NULL)
        return (HMODULE) (ProcEnvBlk->ImageBaseAddress);
    
    PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY * ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY * pStartListEntry = ModuleList->Flink;

    /*------[ITERATE THROUGH THE ELEMENTS OF InMemoryOrderModuleList LINKED LIST]------*/
    for (LIST_ENTRY * pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
        
        /*------[GET CURRENT DATA TABLE ENTRY]------*/
        LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));
    
        /*------[RET THE MODULE BASE ADDRESS IF A MATCH IS FOUND]------*/
        if (strcmp((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
    }

    return NULL;
}

FARPROC WINAPI CustomGetProcAddress(HMODULE hMod, char * sProcName) {
    char * pBaseAddr = (char *) hMod;

    /*------[GET POINTERS TO MAIN HEADERS/STRUCTURES]------*/
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

    /*------[RESOLVE ADDRESSES OF TABLES]------*/
    DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    /*------[FUNCTION WE WANT TO RESOLVE]------*/
    void *pProcAddr = NULL;

    /*------[RESOLVE FUNCTION BY ORDINAL]------*/
    if (((DWORD_PTR)sProcName >> 16) == 0) {
        WORD ordinal = (WORD) sProcName & 0xFFFF; // Convert to WORD
        DWORD Base = pExportDirAddr->Base;  // First ordinal number

        /*------[CHECK IF ORDINAL IS VALID (dll_base_addr + AddressOfFunctions[ordinal - Base])]------*/
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;
        
        /*------[CALCULATE THE FUNCTION VIRTUAL ADDRESS]------*/
        pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
    }

    /*------[RESOLVE FUNCTION BY NAME]------*/
    else {
        /*------[GO THROUGH THE ELEMENTS OF AddressOfNames TABLE]------*/
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];

            if (strcmp(sProcName, sTmpFuncName) == 0) {
                /*------[IF A MACTH IS FOUND, CALCULATE THE FUNCTION VIRTUAL ADDRESS (dll_base_addr + AddressOfFunctions[AddressOfNameOrdinals[i]])]------*/
                pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
                break;
            }
        }
    }

    /*------[CHECK IF FUNCTION RVA IS FORWARDED TO EXTERNAL LIBRARY.FUNCTION]------*/
    
    // if ((char *) pProcAddr >= (char *) pExportDirAddr && (char *) pProcAddr < (char *) (pExportDirAddr + pExportDataDir->Size)) {
    //     char * sFwdDLL = _strdup((char *) pProcAddr);   // Get a copy of library.function string
    //     if (!sFwdDLL) return NULL;

    //     /*------[GET A POINTER TO THE EXTERNAL FUNCTION NAME]------*/
    //     char * sFwdFunction = strchr(sFwdDLL, '.');
    //     *sFwdFunction = 0;      // Set trailing null byte for external library name -> library\x0function
    //     sFwdFunction++;        // Shift a pointer to the beginning of function name

    //     /*------[GET A POINTER TO LoadLibrary FUNCTION]------*/
    //     if (pLoadLibraryA == NULL) {
    //         pLoadLibraryA = (LoadLibraryA_DT) CustomGetProcAddress(CustomGetModuleHandle(L"KERNEL32.DLL"), "LoadLibaryA");
    //         if (pLoadLibraryA == NULL) return NULL;
    //     }

    //     /*------[LOAD EXTERNAL LIBRARY]------*/
    //     HMODULE hFwd = pLoadLibraryA(sFwdDLL);
    //     free(sFwdDLL);          // release the allocated memory for lib.func string copy
    //     if (!hFwd) return NULL; 

    //     /*------[GET ADDRESS OF FUNCTION THE ORIGINAL CALL IS FORWARDED TO]------*/
    //     pProcAddr = CustomGetProcAddress(hFwd, sFwdFunction);   
    // }

    return (FARPROC) pProcAddr;
}