#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
typedef VOID* HPCON;
using FnCreatePseudoConsole = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using FnClosePseudoConsole = VOID(WINAPI*)(HPCON);
static int run(int mode) {
  auto create=(FnCreatePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ClosePseudoConsole");
  SECURITY_ATTRIBUTES sa{sizeof(sa),0,TRUE};
  HANDLE inR,inW,outR,outW;
  CreatePipe(&inR,&inW,&sa,0); CreatePipe(&outR,&outW,&sa,0);
  SetHandleInformation(inW,HANDLE_FLAG_INHERIT,0); SetHandleInformation(outR,HANDLE_FLAG_INHERIT,0);
  COORD sz{80,25}; HPCON hPC=nullptr;
  create(sz,inR,outW,0,&hPC);
  SIZE_T attrBytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&attrBytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrBytes);
  InitializeProcThreadAttributeList(attrs,1,0,&attrBytes);
  void* val = (mode==0) ? (void*)hPC : (void*)&hPC;
  BOOL up=UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,val,sizeof(hPC),nullptr,nullptr);
  printf("mode=%d Update=%d\n", mode, (int)up);
  wchar_t cmd[]=L"cmd.exe /c echo DIAG_MARK_99";
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(si); si.lpAttributeList=attrs;
  PROCESS_INFORMATION pi{};
  BOOL ok=CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi);
  DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs);
  CloseHandle(inR); CloseHandle(outW);
  WaitForSingleObject(pi.hProcess,10000);
  char acc[4096]; size_t al=0; char buf[256]; DWORD n=0;
  while (al+1 < sizeof(acc)) {
    DWORD avail=0;
    if (!PeekNamedPipe(outR,nullptr,0,nullptr,&avail,nullptr)) break;
    if (avail==0) {
      // one blocking read
      if (!ReadFile(outR,buf,sizeof(buf)-1,&n,nullptr) || n==0) break;
    } else {
      if (!ReadFile(outR,buf,sizeof(buf)-1,&n,nullptr) || n==0) break;
    }
    if (al+n >= sizeof(acc)) n=(DWORD)(sizeof(acc)-1-al);
    memcpy(acc+al, buf, n); al+=n; acc[al]=0;
    if (strstr(acc, "DIAG_MARK_99")) break;
  }
  printf("PIPE=[%s]\n", acc);
  int hit = strstr(acc, "DIAG_MARK_99") != nullptr;
  printf("PIPE_HAS_MARK=%d CreateProcess=%d\n", hit, (int)ok);
  close(hPC); CloseHandle(inW); CloseHandle(outR); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return hit?0:1;
}
int main(){ FreeConsole(); int a=run(0); int b=run(1); printf("mode0_rc=%d mode1_rc=%d\n", a,b); return (a==0||b==0)?0:1; }