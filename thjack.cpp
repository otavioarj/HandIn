
#include "main.h"
#include <tlhelp32.h>

#define THREAD_ACCESS (THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |  THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SUSPEND_RESUME )


extern "C" MYWORD Pload(void);
extern "C" void Pload_stub(void);

 DWORD getThreadID( unsigned long pid)
{
   // puts("Getting Thread ID"));
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(h != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if( Thread32First(h, &te))
        {
            do
            {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
                {
                    if(te.th32OwnerProcessID == pid)
                    {
                        HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if(!hThread)
                        {
                            return -1;
                        }
                        else
                        {

                            //qDebug("Got one: %lu\n", te.th32OwnerProcessID);
                            return te.th32ThreadID;
                        }
                    }
                }
            } while( Thread32Next(h, &te));
        }
    }
    CloseHandle(h);
    return ( DWORD)0;
}

int mytrick(DWORD processID,HANDLE hProcess, stubs obj, param p, bool slub)
{
    using namespace andrivet::ADVobfuscator;
    HANDLE hThread,hToken;
    DWORD Plen,Llen;
    PVOID myLoad=NULL,myStub=NULL,mem=NULL,memwipe=NULL,mem2=NULL;
    TOKEN_PRIVILEGES tp;
    CONTEXT ctx;
    //unsigned long int NtGlobalFlags=0;

    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid.LowPart=20; // 20 = SeDebugPrivilege
    tp.Privileges[0].Luid.HighPart=0;
    if(!OpenProcessToken((HANDLE)-1,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
    {
        MMapError(OBFUSCATED4("[-] Not enought permission!"));
        return false;
    }
    AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,0);
    CloseHandle(hToken);

    DWORD threadID = getThreadID(processID);

    if(threadID == (DWORD)0)
     {
        MMapError(OBFUSCATED4("[-] Thread not found"));
        return false;
      }
    MMapError("OpenThr\n");
    hThread=OpenThread( THREAD_ACCESS,FALSE,threadID);

       if(!hThread)
       {
           MMapError(OBFUSCATED4("[-] Can't open thread handle"));
           return false;
       }



       ctx.ContextFlags=CONTEXT_FULL;
       SuspendThread(hThread);

       if(!GetThreadContext(hThread,&ctx)) // Get the thread context
       {
           MMapError(OBFUSCATED4("[-] Can't get thread context"));
           ResumeThread(hThread);
           CloseHandle(hThread);
           return false;
       }


     // hProcess=OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,FALSE,processID);
      if(hProcess==NULL)
      {

          MMapError(OBFUSCATED4("[-] Can't open process!"));
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
      }

      MMapError(NULL);
      mem=VirtualAllocEx(hProcess,NULL,124,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
      mem2=VirtualAllocEx(hProcess,NULL,1024,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

       if(!(( MYWORD)mem & ( MYWORD)mem2 ))
       {

           MMapError(OBFUSCATED4("[-] Can't alloc memory for inject!"));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }
      // qDebug( "Using Thread ID %lu\n", threadID);

          MMapError(NULL);
          Plen=( MYWORD)Pload_stub - ( MYWORD)Pload;
           myStub=(LPVOID)Pload;
           myLoad=(LPVOID)mem2;


       Llen= ( MYWORD) obj.fin - ( MYWORD) obj.in;
     //  myLoad=(LPVOID)mem2;
       //Slen= strlen(dllname);

       if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)myLoad),obj.in,Llen,NULL))
        {
           MMapError(OBFUSCATED4("[-] Can't Continue1."));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           ResumeThread(hThread);
           return false;
        }
        MMapError(NULL);
       if(!myWriteProcessMemory(hProcess,mem,&myLoad,sizeof(PVOID),NULL))
        {
          MMapError(OBFUSCATED4("[-] Can't Continue2."));
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
// EM 64 SÃO 8 BYTES
        if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))),(LPCVOID) myStub,Plen,NULL))
        {
          MMapError(OBFUSCATED4("[-] Can't Continue3."));
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          ResumeThread(hThread);
          CloseHandle(hThread);
          CloseHandle(hProcess);
          return false;
        }
     //  qDebug("Escrito: %#x\n",mem);
   //    if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+4+Plen),dllname,Slen,NULL))

      //qDebug("Addr: %#x AddrData: %#x Tam: %d\n",&p.data,p.data,p.a);
      if(!myWriteProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))+Plen),p.data,p.a,NULL))
       {
         MMapError(OBFUSCATED4("[-] Can't Continue4."));
         VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
         VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
         ResumeThread(hThread);
         CloseHandle(hThread);
         CloseHandle(hProcess);
         return false;
       }

      MMapError("reip value\n");
 //      qDebug("Current esp value: %#x\n",ctx.Esp);
#ifdef _WIN64    // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!
       ctx.Rsp-=0x8;
       myWriteProcessMemory(hProcess,(PVOID)ctx.Rsp,&ctx.Rip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
       ctx.Rip=( MYWORD)((LPBYTE)mem+8);
       //qDebug("Swap rip value: %#x\n",ctx.Rip);
#warning "EH 64"

#else
       ctx.Esp-=0x4;
       myWriteProcessMemory(hProcess,(PVOID)ctx.Esp,&ctx.Eip,sizeof(long int),NULL); // Write orginal eip into target thread's stack
       ctx.Eip=( MYWORD)((LPBYTE)mem+4); // Set eip to the injected shellcode
       //qDebug("Swap eip value: %#x\n",ctx.Eip);

#endif





       if(!SetThreadContext(hThread,&ctx)) // Hijack the thread
       {

           MMapError(OBFUSCATED4("[-] Can't Continue5."));
           VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
           VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
           ResumeThread(hThread);
           CloseHandle(hThread);
           CloseHandle(hProcess);
           return false;
       }

      // QMessageBox::critical(NULL, "Error!",":)");
       ResumeThread(hThread); // Resume the thread to allow the thread execute the shellcode
       CloseHandle(hThread);
      /* HWND hWnd=NULL;
       hWnd=FindWindowFromProcessId(processID);
       if(hWnd==NULL)
         MMapError(OBFUSCATED4("[-] Can't display process windows."));
       else
       {
       ShowWindow(hWnd,SW_SHOWMAXIMIZED);
       ShowWindow(hWnd, SW_RESTORE);
       }*/
   //   HMODULE hMod;
      memwipe=malloc(1024);
      memset(memwipe,0x0,1024);
       MYWORD hMod=0,cnt=0;
       MYWORD * swap=( MYWORD *)p.data;
      do{
      ReadProcessMemory(hProcess,(PVOID)((LPBYTE)mem+(sizeof(MYWORD))+Plen),&hMod,sizeof(hMod),NULL);
      Sleep(50);
      cnt++;
      //qDebug("D: %#x D2 %#x D3 %#x H:%#x\n",(DWORD)p.data,swap,*swap,hMod);
      }
      while(hMod==( MYWORD)*swap && cnt<60);
    //  QMessageBox::critical(NULL, "Error!",":(");
      if (hMod==( MYWORD)*swap)
      {
          MMapError(OBFUSCATED4("[-] Stub timed out! "));
          VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
          VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
          CloseHandle(hProcess);
          free(memwipe);
          return 2;
      }


      myWriteProcessMemory(hProcess,mem,memwipe,124,NULL);
      myWriteProcessMemory(hProcess,mem2,memwipe,1024,NULL);
      VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
      VirtualFreeEx(hProcess,mem2,0,MEM_RELEASE);
      //CloseHandle(hProcess);
      free(memwipe);
      return true;

}

