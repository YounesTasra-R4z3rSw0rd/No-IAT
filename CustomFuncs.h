#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI CustomGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI CustomGetProcAddress(HMODULE hMod, char * sProcName);