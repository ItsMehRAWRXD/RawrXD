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

static int drain_ms(HANDLE h, char* acc, size_t cap, DWORD ms, const char* mark) {
  size_t al=0; acc[0]=0; DWORD t0=GetTickCount();
  while (GetTickCount()-t0 < ms && al+1 < cap) {
    DWORD avail=0;
    if (PeekNamedPipe(h,nullptr,0,nullptr,&avail,nullptr) && avail) {
      char b[512]; DWORD n=0; DWORD want=avail; if (want>sizeof(b)-1) want=sizeof(b)-1;
      if (!ReadFile(h,b,want,&n,nullptr)||!n) break;
      if (al+n>=cap) n=(DWORD)(cap-1-al);
      memcpy(acc+al,b,n); al+=n; acc[al]=0;
      if (mark && strstr(acc,mark)) return 1;
    } else Sleep(15);
  }
  return mark && strstr(acc,mark) ? 1 : 0;
}

// mode bits: 1=&hPC 2=STARTF_USESTDHANDLES null 4=CREATE_SUSPENDED 8=close_pty_before_resume 16=appname_cmd
static int trial(unsigned mode, const char* label) {
  auto create=(FnCreatePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ClosePseudoConsole");
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
  HANDLE inR,inW,outR,outW;
  if (!CreatePipe(&inR,&inW,&sa,0)||!CreatePipe(&outR,&outW,&sa,0)) return 0;
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);

  // Snapshot pipe before CreateProcess — detects CreatePseudoConsole VT seed
  char pre[256]={}; DWORD preN=0; PeekNamedPipe(outR,nullptr,0,nullptr,&preN,nullptr);
  if (preN) { ReadFile(outR,pre,min(preN,(DWORD)sizeof(pre)-1),&preN,nullptr); pre[preN]=0; }

  COORD sz{120,30}; HPCON hPC=nullptr;
  HRESULT hr=create(sz,inR,outW,0,&hPC);
  if (FAILED(hr)||!hPC) { printf("%s CreatePC fail\n", label); return 0; }

  // bytes after CreatePseudoConsole alone
  char seed[256]={}; DWORD seedAvail=0;
  PeekNamedPipe(outR,nullptr,0,nullptr,&seedAvail,nullptr);
  if (seedAvail) {
    DWORD n=0; ReadFile(outR,seed,min(seedAvail,(DWORD)sizeof(seed)-1),&n,nullptr); seed[n]=0;
  }

  SIZE_T bytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
  InitializeProcThreadAttributeList(attrs,1,0,&bytes);
  void* val = (mode&1) ? (void*)&hPC : (void*)hPC;
  if (!UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,val,sizeof(HPCON),nullptr,nullptr)) {
    printf("%s Update fail %lu\n", label, GetLastError()); return 0;
  }

  STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  si.lpAttributeList = attrs;
  si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  si.StartupInfo.wShowWindow = SW_HIDE;
  if (mode & 2) {
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nullptr;
    si.StartupInfo.hStdOutput = nullptr;
    si.StartupInfo.hStdError = nullptr;
  }
  DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
  if (mode & 4) flags |= CREATE_SUSPENDED;

  wchar_t cmdLine[128];
  wcscpy_s(cmdLine, L"cmd.exe /c echo CONPTY_MARK_A7F3");
  PROCESS_INFORMATION pi{};
  BOOL ok;
  if (mode & 16) {
    ok = CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", cmdLine, nullptr, nullptr, FALSE,
                        flags, nullptr, nullptr, &si.StartupInfo, &pi);
  } else {
    ok = CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
                        flags, nullptr, nullptr, &si.StartupInfo, &pi);
  }
  DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs);

  if (mode & 8) { CloseHandle(inR); CloseHandle(outW); inR=outW=nullptr; }

  if (!ok) {
    printf("%s CreateProcess fail %lu\n", label, GetLastError());
    if (inR) CloseHandle(inR); if (outW) CloseHandle(outW);
    close(hPC); CloseHandle(inW); CloseHandle(outR); return 0;
  }
  if (mode & 4) ResumeThread(pi.hThread);
  if (!(mode & 8)) { CloseHandle(inR); CloseHandle(outW); }

  char acc[8192];
  int hit = drain_ms(outR, acc, sizeof(acc), 5000, "CONPTY_MARK_A7F3");
  WaitForSingleObject(pi.hProcess, 2000);
  drain_ms(outR, acc, sizeof(acc), 300, nullptr);

  printf("%s hit=%d seed_len=%zu seed=[%.80s] pipe_len=%zu pipe=[%.240s]\n",
         label, hit, strlen(seed), seed, strlen(acc), acc);

  close(hPC); CloseHandle(inW); CloseHandle(outR);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return hit;
}

int main() {
  // Do NOT FreeConsole — keep parent console; detect leak separately
  printf("MATRIX_V2\n");
  fflush(stdout);
  int w=0;
  w+=trial(0,    "hPC");
  w+=trial(1,    "amp");
  w+=trial(1|2,  "amp_stdnull");
  w+=trial(1|4|8,"amp_sus_close");
  w+=trial(1|2|4|8,"amp_stdnull_sus_close");
  w+=trial(1|2|4|8|16,"amp_stdnull_sus_close_app");
  w+=trial(0|2|4|8,"hPC_stdnull_sus_close");
  printf("WINS=%d\n", w);
  return w>0?0:1;
}