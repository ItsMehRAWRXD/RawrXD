#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
#ifndef HPCON
typedef VOID* HPCON;
#endif
using FnCreatePseudoConsole = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using FnClosePseudoConsole = VOID(WINAPI*)(HPCON);

// Overlapped named-pipe ConPTY probe — read WHILE process runs (not after wait).
static int run_named(int pass_addr) {
  auto create = (FnCreatePseudoConsole)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "CreatePseudoConsole");
  auto close = (FnClosePseudoConsole)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "ClosePseudoConsole");
  if (!create || !close) {
    printf("API_MISSING\n");
    return 2;
  }

  FreeConsole();

  wchar_t pipeInName[64], pipeOutName[64];
  swprintf_s(pipeInName, L"\\\\.\\pipe\\rawrxd_conpty_in_%lu", GetCurrentProcessId());
  swprintf_s(pipeOutName, L"\\\\.\\pipe\\rawrxd_conpty_out_%lu", GetCurrentProcessId());

  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};

  HANDLE hPipeInServer = CreateNamedPipeW(
      pipeInName, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, &sa);
  HANDLE hPipeOutServer = CreateNamedPipeW(
      pipeOutName, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, &sa);
  if (hPipeInServer == INVALID_HANDLE_VALUE ||
      hPipeOutServer == INVALID_HANDLE_VALUE) {
    printf("named_pipe_server_fail err=%lu\n", GetLastError());
    return 3;
  }

  HANDLE hPipeInClient = CreateFileW(pipeInName, GENERIC_READ | FILE_WRITE_ATTRIBUTES,
                                     0, &sa, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  HANDLE hPipeOutClient = CreateFileW(pipeOutName, GENERIC_WRITE | FILE_READ_ATTRIBUTES,
                                      0, &sa, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  if (hPipeInClient == INVALID_HANDLE_VALUE ||
      hPipeOutClient == INVALID_HANDLE_VALUE) {
    printf("named_pipe_client_fail err=%lu\n", GetLastError());
    return 4;
  }
  ConnectNamedPipe(hPipeInServer, nullptr);
  ConnectNamedPipe(hPipeOutServer, nullptr);

  // ConPTY: input=read end for pty, output=write end for pty
  COORD sz{80, 25};
  HPCON hPC = nullptr;
  HRESULT hr = create(sz, hPipeInClient, hPipeOutClient, 0, &hPC);
  printf("pass_addr=%d hr=0x%08lX hPC=%p\n", pass_addr, (unsigned long)hr, (void*)hPC);
  if (FAILED(hr) || !hPC) return 5;

  SIZE_T attrBytes = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attrBytes);
  auto* attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrBytes);
  InitializeProcThreadAttributeList(attrs, 1, 0, &attrBytes);
  PVOID val = pass_addr ? (PVOID)&hPC : (PVOID)hPC;
  BOOL up = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                      val, sizeof(HPCON), nullptr, nullptr);
  printf("Update=%d\n", (int)up);

  wchar_t cmd[] = L"cmd.exe /c echo DIAG_MARK_99";
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  si.lpAttributeList = attrs;
  PROCESS_INFORMATION pi{};
  BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                           EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                           nullptr, nullptr, &si.StartupInfo, &pi);
  printf("CreateProcess=%d err=%lu\n", (int)ok, GetLastError());
  DeleteProcThreadAttributeList(attrs);
  HeapFree(GetProcessHeap(), 0, attrs);
  // Close PTY-side ends we duplicated into ConPTY
  CloseHandle(hPipeInClient);
  CloseHandle(hPipeOutClient);

  char acc[8192];
  size_t al = 0;
  DWORD t0 = GetTickCount();
  while (GetTickCount() - t0 < 8000 && al + 1 < sizeof(acc)) {
    char buf[512];
    DWORD n = 0;
    DWORD avail = 0;
    if (PeekNamedPipe(hPipeOutServer, nullptr, 0, nullptr, &avail, nullptr) && avail) {
      if (ReadFile(hPipeOutServer, buf, sizeof(buf) - 1, &n, nullptr) && n) {
        if (al + n >= sizeof(acc)) n = (DWORD)(sizeof(acc) - 1 - al);
        memcpy(acc + al, buf, n);
        al += n;
        acc[al] = 0;
        if (strstr(acc, "DIAG_MARK_99")) break;
      }
    } else {
      DWORD w = WaitForSingleObject(pi.hProcess, 50);
      if (w == WAIT_OBJECT_0) {
        // drain remaining
        while (PeekNamedPipe(hPipeOutServer, nullptr, 0, nullptr, &avail, nullptr) &&
               avail && al + 1 < sizeof(acc)) {
          if (!ReadFile(hPipeOutServer, buf, sizeof(buf) - 1, &n, nullptr) || !n) break;
          if (al + n >= sizeof(acc)) n = (DWORD)(sizeof(acc) - 1 - al);
          memcpy(acc + al, buf, n);
          al += n;
          acc[al] = 0;
        }
        break;
      }
    }
  }
  acc[al] = 0;
  printf("PIPE_LEN=%zu PIPE=[%s]\n", al, acc);
  int hit = strstr(acc, "DIAG_MARK_99") != nullptr;
  printf("PIPE_HAS_MARK=%d\n", hit);

  close(hPC);
  CloseHandle(hPipeInServer);
  CloseHandle(hPipeOutServer);
  if (pi.hProcess) CloseHandle(pi.hProcess);
  if (pi.hThread) CloseHandle(pi.hThread);
  return hit ? 0 : 1;
}

int main() {
  SetConsoleOutputCP(CP_UTF8);
  int a = run_named(0);
  int b = run_named(1);
  printf("result_pass_value=%d result_pass_addr=%d\n", a, b);
  return (a == 0 || b == 0) ? 0 : 1;
}
