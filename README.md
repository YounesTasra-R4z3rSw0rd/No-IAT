## Techniques implemented in the malware:

1. AES Encrypted Shellcode.
2. Custom `GetProcAddress` and `GetModuleHandle`
3. Function Calls Obfuscation
4. String Obfuscation
5. GUI executable (`WinMain` being the entrypoint)
6. Import Address Table is stripped from the executable. (*Zero-Imports*)

## 'CustomGetModuleHandle' Function:

1. The function takes as parameter: 
	* `LPCWSTR sModuleName` : The name of the loaded module - *e.g. `Kernel32.dll`*
2. Access the Process Environment Block - PEB for the current process.
	* PEB pointer is located in TEB at offset `0x60` in **x64 arch**
	* PEB pointer is located in TEB at offset `0x30` in **x86 arch**
3. The function returns the base address of the calling, if no module has been provided.
4. Inside the PEB, there is a structure called `Ldr`, which has information about the loaded DLL within a process. The function iterates through the elements of the linked list `InMemoryOrderModuleList`, which is one of the element of `Ldr` structure (`_PEB` -> `_PEB_LDR_DATA` -> `InMemoryOrderModuleList`). The `InMemoryOrderModuleList` contains names of loaded modules in the memory address space of the current process.
5. Iterates through the elements of `InMemoryOrderModuleList`. The function compares each element of the list with the provided module and returns the base address of the module (*provided DLL name*) when a match is found. The function returns NULL if no match was found.

## 'CustomGetProcAddress' Function

1. The function takes as parameter: 
	* `HMODULE hMod` : A handle to a DLL Module. This handle is obtained from `GetModuleHandle`
	* `char * sProcName` : The function or variable name. This parameter can be an ordinal.
2. Access the **Export Data Directory** by parsing the main headers and structures of the provided module.
	* `IMAGE_DOS_HEADER` -> `IMAGE_NT_HEADERS` -> `IMAGE_OPTIONAL_HEADER` -> `IMAGE_DATA_DIRECTORY`
	* Get the base address of Export Directory - `pExportDirAddr`
3. Get the base address of the tables inside the Export Directory:
	* **Export Address Table** - `AddressOfFunctions`
	* **Function Name Table** - `AddressOfNames`
	* **Table of ordinals** - `AddressOfNameOrdinals`
4. Check whether **`sProcName`** is a string (*function name*) or ordinal.
5. If **`sProcName`** is ordinal, the function extracts the `Base` ordinal value from the **Export Directory** and performs some checks on **`sProcName`** before attempting to resolve the function. If everything's good, the function retrieves the address from `AddressOfFunctions` array at index `ordinal - Base` and resolves the address of **`sProcName`** by calculating: `dllBaseAddr + AddressOfFunctions[ordinal - Base]`
6. If **`sProcName`** is a string, the function iterates through the elements of `AddressOfNames` and compares each element with **`sProcName`**.
7. When a match is found at position `i`, the function refers to `AddressOfNameOrdinals` to retrieve the ordinal associated to **`sProcName`**.
8. Next, the function refers to `AddressOfFunctions[AddressOfNameOrdinals[i]]` element, which is the RVA associated to **`sProcName`**.
9. After that, the function calculates the virtual address of **`sProcName`**: `dllBaseAddr + AddressOfFunctions[AddressOfNameOrdinals[i]]`
10. Finally, the function does an optional step, in which it checks if the RVA is forwarded to an external library function. If it's the case, the function loads the external library in memory and retrieves the address of the function that the original call is forwarded to using **`CustomGetProcAddress`**.

## Execution
### poc-xor.cpp

![Zero-Imports-XOR](https://github.com/YounesTasra-R4z3rSw0rd/MalDev/assets/101610095/9240367f-f863-4032-88a1-5a667d8572ff)


### poc-aes.cpp

![Zero-Imports-AES](https://github.com/YounesTasra-R4z3rSw0rd/MalDev/assets/101610095/cbd95f1a-d283-432d-a90b-e7fe951e9ec1)



