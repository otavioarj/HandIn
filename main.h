#ifndef __MAIN_H__
#define __MAIN_H__

#define _WIN32_WINNT 0x0600
//#define WIN32_LEAN_AND_MEAN
#include <windows.h>
//#define OBFUSCATED4(x) x
#define MYWORD DWORD64
#include "../ADVobfuscator/ADVobfuscator/MetaString4.h"



typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

struct stubs
{
  void *in ;
  void *fin;

};

struct param
{
    void *data;
    unsigned int a;
};

BOOL Verifier(IN PVOID pvReserved);

void WINAPI LoadDllEnd();
MYWORD WINAPI LoadDll2(PVOID p);
int ServiceEnumHandles(ULONG ProcessId, DWORD dwDesiredAccess, char * path);

void MMapError(const char * str);
BOOL myWriteProcessMemory(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
int mytrick(DWORD processID,HANDLE hProcess, stubs obj, param p, bool slub);
DWORD WINAPI InstanceThread(LPVOID);

int mmap(DWORD ProcessId, HANDLE hProcess,char* dll);

typedef NTSTATUS (NTAPI *pZwWriteVirtualMemory)(IN HANDLE               ProcessHandle,
                                                 IN PVOID                BaseAddress,
                                                 IN LPCVOID                Buffer,
                                                 IN ULONG                NumberOfBytesToWrite,
                                                 OUT SIZE_T  *           NumberOfBytesWritten);

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE,LPCSTR);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT;



#endif // __MAIN_H__
