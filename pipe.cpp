#include "main.h"
//#include <stdio.h>
//#include <tchar.h>

#define BUFSIZE 512


DWORD InstanceThread(LPVOID lpvParam)
{
    HANDLE hHeap      = GetProcessHeap();
    CHAR* pchRequest = (CHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(CHAR));
    CHAR* pchReply   = (CHAR*)HeapAlloc(hHeap, 0, BUFSIZE*sizeof(CHAR));
    char * path=NULL;


    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0, pid =0, daccess=0;
    BOOL fSuccess = FALSE;
    HANDLE hPipe  = NULL;



    if (lpvParam == NULL)
    {
        // printf( "\nERROR - Pipe Server Failure:\n");
        // printf( "   InstanceThread got an unexpected NULL value in lpvParam.\n");
        // printf( "   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return 0;
    }

    if (pchRequest == NULL)
    {
        // printf( "\nERROR - Pipe Server Failure:\n");
        // printf( "   InstanceThread got an unexpected NULL heap allocation.\n");
        // printf( "   InstanceThread exitting.\n");
        if (pchReply != NULL) HeapFree(hHeap, 0, pchReply);
        return 0;
    }

    if (pchReply == NULL)
    {
        //printf( "\nERROR - Pipe Server Failure:\n");
        //printf( "   InstanceThread got an unexpected NULL heap allocation.\n");
        // printf( "   InstanceThread exitting.\n");
        if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
        return 0;
    }

    hPipe = (HANDLE) lpvParam;
    while(!cbBytesRead)
    {
        fSuccess = ReadFile(
                       hPipe,        // handle to pipe
                       pchRequest,    // buffer to receive data
                       BUFSIZE*sizeof(CHAR), // size of buffer
                       &cbBytesRead, // number of bytes read
                       NULL);        // not overlapped I/O
        Sleep(50);
    }



    if (!fSuccess)
    {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        HeapFree(hHeap, 0, pchRequest);
        HeapFree(hHeap, 0, pchReply);
        return 0;
    }
    path=(CHAR*)HeapAlloc(hHeap, 0, 256*sizeof(CHAR));
    sscanf(pchRequest,"%d %d %s ",&pid,&daccess,path);

    MMapError(pchRequest);
    sprintf(pchReply,"R: %d \n0",ServiceEnumHandles((ULONG) pid, daccess,path));
    WriteFile(hPipe,pchReply,strlen(pchReply),&cbBytesRead,NULL);

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    HeapFree(hHeap, 0, pchRequest);
    HeapFree(hHeap, 0, pchReply);
    HeapFree(hHeap, 0, path);

    return 1;
}


