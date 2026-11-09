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

static int make_pipes(int named, HANDLE* inR, HANDLE* inW, HANDLE* outR, HANDLE* outW) {
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  if (!named) {
    if (!CreatePipe(inR, inW, &sa, 0)) return 0;
    if (!CreatePipe(outR, outW, &sa, 0)) return 0;
  } else {
    char n1[64], n2[64];
    sprintf_s(n1, "\\\\.\\pipe\\rawr_conpty_in_%lu", GetCurrentProcessId());
    sprintf_s(n2, "\\\\.\\pipe\\rawr_conpty_out_%lu", GetCurrentProcessId());
    *inR = CreateNamedPipeA(n1, PIPE_ACCESS_INBOUND,
      PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT, 1, 4096, 4096, 0, &sa);
    *inW = CreateFileA(n1, GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, nullptr);
    *outW = CreateNamedPipeA(n2, PIPE_ACCESS_OUTBOUND,
      PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT, 1, 4096, 4096, 0, &sa);
    *outR = CreateFileA(n2, GENERIC_READ, 0, &sa, OPEN_EXISTING, 0, nullptr);
    if (*inR==INVALID_HANDLE_VALUE||*inW==INVALID_HANDLE_VALUE||
        *outR==INVALID_HANDLE_VALUE||*outW==INVALID_HANDLE_VALUE) return 0;
  }
  SetHandleInformation(*inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(*outR, HANDLE_FLAG_INHERIT, 0);
  return 1;
}

static int drain(HANDLE outR, char* acc, size_t accMax, DWORD waitMs, const char* mark) {
  size_t al = 0; acc[0]=0;
  DWORD t0 = GetTickCount();
  while (GetTickCount()-t0 < waitMs && al+1 < accMax) {
    DWORD avail=0;
    if (PeekNamedPipe(outR, nullptr, 0, nullptr, &avail, nullptr) && avail>0) {
      char buf[512]; DWORD n=0;
      DWORD toRead = avail; if (toRead > sizeof(buf)-1) toRead = sizeof(buf)-1;
      if (!ReadFile(outR, buf, toRead, &n, nullptr) || n==0) break;
      if (al+n >= accMax) n = (DWORD)(accMax-1-al);
      memcpy(acc+al, buf, n); al+=n; acc[al]=0;
      if (mark && strstr(acc, mark)) return 1;
    } else {
      Sleep(20);
    }
  }
  return (mark && strstr(acc, mark)) ? 1 : 0;
}

// flags: bit0=named, bit1=use_amp_hPC, bit2=suspended, bit3=freeconsole already done outside
static int trial(int named, int amp, int suspended, const char* label) {
  auto create=(FnCreatePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreatePseudoConsole");
  auto close=(FnClosePseudoConsole)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ClosePseudoConsole");
  HANDLE inR=0,inW=0,outR=0,outW=0;
  if (!make_pipes(named, &inR,&inW,&outR,&outW)) {
    printf("%s PIPE_FAIL\n", label); return 0;
  }
  COORD sz{80,25}; HPCON hPC=nullptr;
  HRESULT hr=create(sz, inR, outW, 0, &hPC);
  if (FAILED(hr)||!hPC) { printf("%s CreatePC_FAIL hr=%08lX\n", label, (unsigned long)hr); return 0; }

  SIZE_T bytes=0; InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
  auto* attrs=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,bytes);
  InitializeProcThreadAttributeList(attrs,1,0,&bytes);
  void* val = amp ? (void*)&hPC : (void*)hPC;
  if (!UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,val,sizeof(hPC),nullptr,nullptr)) {
    printf("%s Update_FAIL err=%lu\n", label, GetLastError());
    close(hPC); return 0;
  }

  wchar_t cmd[] = L"cmd.exe /c echo CONPTY_MARK_A7F3";
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(si); si.lpAttributeList=attrs;
  si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
  si.StartupInfo.wShowWindow = SW_HIDE;
  // Explicitly do NOT set STARTF_USESTDHANDLES
  DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
  if (suspended) flags |= CREATE_SUSPENDED;
  PROCESS_INFORMATION pi{};
  BOOL ok=CreateProcessW(nullptr,cmd,nullptr,nullptr,FALSE,flags,nullptr,nullptr,&si.StartupInfo,&pi);
  DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(),0,attrs);
  // Close PTY-side handles (MSDN)
  CloseHandle(inR); CloseHandle(outW);
  if (!ok) {
    printf("%s CreateProcess_FAIL err=%lu\n", label, GetLastError());
    close(hPC); CloseHandle(inW); CloseHandle(outR); return 0;
  }
  if (suspended) ResumeThread(pi.hThread);

  char acc[8192];
  int hit = drain(outR, acc, sizeof(acc), 4000, "CONPTY_MARK_A7F3");
  WaitForSingleObject(pi.hProcess, 3000);
  // drain leftover
  drain(outR, acc, sizeof(acc), 500, nullptr);

  printf("%s hit=%d pipe_len=%zu pipe=[%.200s]\n", label, hit, strlen(acc), acc);
  close(hPC); CloseHandle(inW); CloseHandle(outR);
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  return hit;
}

int main() {
  // Isolate from parent console so child cannot leak echo to our stdout
  FreeConsole();
  FILE* f=nullptr; freopen_s(&f, "logs\\matrix_out.txt", "w", stdout);
  freopen_s(&f, "logs\\matrix_out.txt", "a", stderr);

  printf("CONPTY_CAPTURE_MATRIX OS\n");
  int wins=0;
  wins += trial(0,0,0, "anon_hPC_nosus");
  wins += trial(0,1,0, "anon_amp_nosus");
  wins += trial(0,0,1, "anon_hPC_sus");
  wins += trial(0,1,1, "anon_amp_sus");
  wins += trial(1,0,0, "named_hPC_nosus");
  wins += trial(1,1,0, "named_amp_nosus");
  wins += trial(1,0,1, "named_hPC_sus");
  wins += trial(1,1,1, "named_amp_sus");
  printf("WINS=%d\n", wins);
  printf("BEST_MARK_IN_PIPE=%s\n", wins>0 ? "1" : "0");
  fflush(stdout);
  return wins>0 ? 0 : 1;
}