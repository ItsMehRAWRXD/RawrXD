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

int main() {
  auto create=(FnCreatePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ClosePseudoConsole");
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
  HANDLE inR,inW,outR,outW;
  CreatePipe(&inR,&inW,&sa,0); CreatePipe(&outR,&outW,&sa,0);
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  COORD sz{80,25}; HPCON hPC=nullptr;
  create(sz,inR,outW,0,&hPC);
  SIZE_T bytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
  InitializeProcThreadAttributeList(attrs,1,0,&bytes);
  // WINNER: pass hPC (not &hPC)
  UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,hPC,sizeof(hPC),nullptr,nullptr);
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(STARTUPINFOEXW);
  si.lpAttributeList=attrs;
  si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.StartupInfo.wShowWindow = SW_HIDE;
  si.StartupInfo.hStdInput = nullptr;
  si.StartupInfo.hStdOutput = nullptr;
  si.StartupInfo.hStdError = nullptr;
  wchar_t cmd[]=L"cmd.exe /c echo CONPTY_MARK_A7F3";
  PROCESS_INFORMATION pi{};
  BOOL ok=CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,
    EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT|CREATE_SUSPENDED,
    nullptr,nullptr,&si.StartupInfo,&pi);
  DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs);
  // Close PTY-side BEFORE resume
  CloseHandle(inR); CloseHandle(outW);
  ResumeThread(pi.hThread);
  char acc[8192]={}; size_t al=0; DWORD t0=GetTickCount();
  while (GetTickCount()-t0 < 5000 && al+1<sizeof(acc)) {
    DWORD avail=0;
    if (PeekNamedPipe(outR,nullptr,0,nullptr,&avail,nullptr) && avail) {
      char b[512]; DWORD n=0; DWORD want=avail; if(want>sizeof(b)-1) want=sizeof(b)-1;
      if (!ReadFile(outR,b,want,&n,nullptr)||!n) break;
      if (al+n>=sizeof(acc)) n=(DWORD)(sizeof(acc)-1-al);
      memcpy(acc+al,b,n); al+=n; acc[al]=0;
      if (strstr(acc,"CONPTY_MARK_A7F3")) break;
    } else Sleep(15);
  }
  WaitForSingleObject(pi.hProcess,2000);
  int hit = strstr(acc,"CONPTY_MARK_A7F3")!=nullptr;
  printf("VERIFY hit=%d pipe_len=%zu\n", hit, al);
  printf("PIPE=[%s]\n", acc);
  printf("MARKER_IN_PIPE=%d\n", hit);
  close(hPC); CloseHandle(inW); CloseHandle(outR);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return hit?0:1;
}