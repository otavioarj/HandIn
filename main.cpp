#include "main.h"
#include <tlhelp32.h>

#define BUFSIZE 512
FILE *p;
int chk=0;
HANDLE hPipe = INVALID_HANDLE_VALUE;

void MMapError(const char * str)
{
    if(chk==-2)
        return;
    if(!str)
        fprintf(p,"Ck: %d\n",++chk);
    else
        fprintf(p,"%s\n",str);
    fflush(p);
}

/*
const wchar_t *GetWC(const char *c)
{
    const size_t cSize = strlen(c)+1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs (wc, c, cSize);

    return wc;
}*/

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

HRESULT __fastcall UnicodeToAnsi(wchar_t * pszW, LPSTR* ppszA,ULONG cCharacters)
{

    ULONG cbAnsi;// cCharacters;
    DWORD dwError;

    // If input is null then just return the same.
    if (pszW == NULL)
    {
        *ppszA = NULL;
        return NOERROR;
    }

    // cCharacters = wcslen(pszW)+1;
    // Determine number of bytes to be allocated for ANSI string. An
    // ANSI string can have at most 2 bytes per character (for Double
    // Byte Character Strings.)
    cbAnsi = cCharacters*2;

    // Use of the OLE allocator is not required because the resultant
    // ANSI  string will never be passed to another COM component. You
    // can use your own allocator.
    *ppszA = (LPSTR) CoTaskMemAlloc(cbAnsi);
    if (NULL == *ppszA)
        return E_OUTOFMEMORY;

    // Convert to ANSI.
    if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA,
                                 cbAnsi, NULL, NULL))
    {
        dwError = GetLastError();
        CoTaskMemFree(*ppszA);
        *ppszA = NULL;
        return HRESULT_FROM_WIN32(dwError);
    }
    return NOERROR;

}


TCHAR * pid2name(DWORD pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnapshot)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if(Process32First(hSnapshot, &pe32))
        {
            do
            {
                if(pe32.th32ProcessID == pid)
                {
                    CloseHandle(hSnapshot);
                    return pe32.szExeFile;
                }
            }
            while(Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return NULL;
    }
}

//http://www.cplusplus.com/forum/windows/95774/

int ServiceEnumHandles(ULONG ProcessId, DWORD dwDesiredAccess, char * path)
{
    typedef NTSTATUS(NTAPI*_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    static _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)(GetProcAddress(GetModuleHandle("ntdll.dll"),"NtQuerySystemInformation"));

    typedef NTSTATUS (NTAPI *_NtQueryObject)(
        HANDLE ObjectHandle,
        ULONG ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength
    );
    _NtQueryObject NtQueryObject =(_NtQueryObject) (GetProcAddress(GetModuleHandle("ntdll.dll"),"NtQueryObject"));
    if(!(ProcessId && dwDesiredAccess && path ))
    {
        MMapError("NUUULL\n");
        return 0;
    }

    typedef struct _SYSTEM_HANDLE
    {
        ULONG ProcessId;
        BYTE ObjectTypeNumber;
        BYTE Flags;
        USHORT Handle;
        PVOID Object;
        ACCESS_MASK GrantedAccess;
    } SYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG HandleCount;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION;

    SYSTEM_HANDLE_INFORMATION *handleInfo = 0;
    NTSTATUS status = -1;
    PVOID buffer = 0;
    ULONG bufferSize = 0, retlen=0;
//    HANDLE ProcessHandle = 0, ProcessCopy = 0;
    // HANDLE_INFO hi = { 0,0 };
    SYSTEM_HANDLE *handle;
    UNICODE_STRING objectName;

    if (!NtQuerySystemInformation)
        return 0;


aloc:
    //MMapError("Alloc\n");
    status = NtQuerySystemInformation(0x10, buffer, bufferSize, &bufferSize);
    if (status)
    {
        if (status ==(NTSTATUS) 0xc0000004)
        {
            if (buffer != NULL)
                VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
            buffer = VirtualAlloc(0, bufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            //MMapError("Goto\n");
            goto aloc;
        }
        else
        {
            if (buffer != NULL)
                VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
            return 0;
        }
    }
    else
    {
        MMapError("For\n");
        handleInfo = (SYSTEM_HANDLE_INFORMATION *)(buffer);
        //itera em todos os handles do SISTEMA!! handle->pid é o pid de um processo que tem handles
        for (unsigned i = 0; i < handleInfo->HandleCount; i++)
        {
            //MMapError(NULL);
            handle = &handleInfo->Handles[i];
            if ((handle->ProcessId != GetCurrentProcessId()) || (handle->GrantedAccess != dwDesiredAccess))
                continue;


            PVOID objectNameInfo;
            objectNameInfo = malloc(0x1000);
            if (!NT_SUCCESS(NtQueryObject(
                                (HANDLE)handle->Handle,
                                ObjectNameInformation,
                                objectNameInfo,
                                0x1000,
                                &retlen
                            )))
            {
                /* Reallocate the buffer and try again. */
                objectNameInfo = realloc(objectNameInfo, retlen);
                if (!NT_SUCCESS(NtQueryObject(
                                    (HANDLE)handle->Handle,
                                    ObjectNameInformation,
                                    objectNameInfo,
                                    retlen,
                                    NULL
                                )))
                {
                    /* We have the type name, so just display that. */
                    char str[128];
                    sprintf(str,"[%#x]: (could not get name)\n",handle->Handle);
                    MMapError(str);
                    free(objectNameInfo);
                    continue;
                }
            }

            objectName = *(PUNICODE_STRING)objectNameInfo;
            if(!objectName.Length)
            {
                MMapError("Nome NULL\n");
                continue;
            }

            char *objnam;
            UnicodeToAnsi(objectName.Buffer,&objnam,objectName.Length);
            if(strcmp(objnam,pid2name(ProcessId)))
            {
                VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
                char str[256];
                sprintf(str,"%d %u %s \n",ProcessId,&handle->Handle,path);
                MMapError(str);

                HANDLE hl=(HANDLE)handle->Handle;
                MMapError("MMAP\n");
                return  mmap(ProcessId,hl,path);
            }
        }
    }

    return 0;
}


DWORD WINAPI Roda( void * a)
{
        MMapError("Entrou Roda\n");
        BOOL   fConnected = FALSE;
        DWORD  dwThreadId = 0;
        LPTSTR lpszPipename;
        lpszPipename =(LPTSTR) malloc(64);
        strcpy(lpszPipename,"\\\\.\\pipe\\kilpipe");
         MMapError(NULL);
        hPipe = CreateNamedPipe(
                    lpszPipename,             // pipe name
                    PIPE_ACCESS_DUPLEX,       // read/write access
                    PIPE_TYPE_MESSAGE |       // message type pipe
                    PIPE_READMODE_MESSAGE |   // message-read mode
                    PIPE_WAIT,                // blocking mode
                    PIPE_UNLIMITED_INSTANCES, // max. instances
                    BUFSIZE,                  // output buffer size
                    BUFSIZE,                  // input buffer size
                    0,                        // client time-out
                    NULL);                    // default security attribute
                     MMapError(NULL);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
             MMapError("Hand Pipe error\n");
             return 0;
        }

           MMapError(NULL);
        fConnected = ConnectNamedPipe(hPipe, NULL) ?
                     TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
           MMapError(NULL);

        if (fConnected)
        {
            // Create a thread for this client.
         /*   hThread = CreateThread(
                          NULL,              // no security attribute
                          0,                 // default stack size
                          InstanceThread,    // thread proc
                          (LPVOID) hPipe,    // thread parameter
                          0,                 // not suspended
                          &dwThreadId);      // returns thread ID*/
               MMapError(NULL);
            if (!InstanceThread(hPipe)) //(!hThread)
                 MMapError("Inta FAIL\n");
            MMapError(NULL);

        }
        else
            // The client could not connect, so close the pipe.
            CloseHandle(hPipe);
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID pvReserved)
{



    if(fdwReason==0x4)  //VERIFIERDLL_DLL_PROCESS_VERIFIER
        return Verifier(pvReserved);
    else if(fdwReason==DLL_PROCESS_ATTACH)
    {
        HANDLE hThread = NULL;
        p=fopen("C:\\Users\\Mobe\\Desktop\\Saida.txt","a"); //D:\\Dropbox\\Win\\Projetos\\HandIn\\bin\\Release\\Out.txt","a");//("D:\\Dropbox\\Win\\Projetos\\PipeClient\\bin\\Release\\Out.txt","a");
        if(!p)
            chk=-2;
        MMapError("Entrou!\n");

         hThread = CreateThread(
                          NULL,              // no security attribute
                          0,                 // default stack size
                          Roda,    // thread proc
                          NULL,    // thread parameter
                          0,                 // not suspended
                          0);      // returns thread ID*/
            if (!hThread)
                 MMapError("Thread FAIL\n");

    }
    else if(fdwReason==DLL_PROCESS_DETACH)
    {
        fclose(p);
        CloseHandle(hPipe);
    }
    return TRUE; // succesful
}
