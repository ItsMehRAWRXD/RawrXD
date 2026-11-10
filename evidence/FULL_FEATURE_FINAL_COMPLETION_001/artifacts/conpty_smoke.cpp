#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif
using CreatePseudoConsole_fn = HRESULT(WINAPI*)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
using ClosePseudoConsole_fn = void(WINAPI*)(HPCON);
using ResizePseudoConsole_fn = HRESULT(WINAPI*)(HPCON, COORD);
int wmain() {
  auto createPC = reinterpret_cast<CreatePseudoConsole_fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreatePseudoConsole"));
  auto closePC = reinterpret_cast<ClosePseudoConsole_fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ClosePseudoConsole"));
  if (!createPC || !closePC) { std::wcout << L"API_ABSENT=1\n"; return 2; }
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  HANDLE inR=nullptr, inW=nullptr, outR=nullptr, outW=nullptr;
  if (!CreatePipe(&inR,&inW,&sa,0) || !CreatePipe(&outR,&outW,&sa,0)) { std::wcout << L"PIPE_FAIL=1\n"; return 3; }
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  HPCON hPC=nullptr; COORD size{80,25};
  HRESULT hr = createPC(size, inR, outW, 0, &hPC);
  if (FAILED(hr) || !hPC) { std::wcout << L"CREATE_FAIL=0x" << std::hex << hr << L"\n"; return 4; }
  SIZE_T attrSize=0; InitializeProcThreadAttributeList(nullptr,1,0,&attrSize);
  auto attr=(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attrSize);
  InitializeProcThreadAttributeList(attr,1,0,&attrSize);
  UpdateProcThreadAttribute(attr,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,hPC,sizeof(hPC),nullptr,nullptr);
  STARTUPINFOEXW si{}; si.StartupInfo.cb=sizeof(si); si.lpAttributeList=attr;
  PROCESS_INFORMATION pi{};
  wchar_t cmd[] = L"cmd.exe /c echo CONPTY_SMOKE_OK& exit /b 0";
  BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi);
  DWORD err = ok ? 0 : GetLastError();
  if (ok) { WaitForSingleObject(pi.hProcess, 5000); DWORD ec=1; GetExitCodeProcess(pi.hProcess,&ec); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); std::wcout << L"CREATEPROCESS_OK=1 EXIT=" << ec << L"\n"; }
  else { std::wcout << L"CREATEPROCESS_FAIL err=" << err << L"\n"; }
  char buf[512]; DWORD n=0; std::string out; while (PeekNamedPipe(outR,nullptr,0,nullptr,&n,nullptr) && n) { DWORD rd=0; if (!ReadFile(outR,buf,sizeof(buf),&rd,nullptr)||!rd) break; out.append(buf,buf+rd); if (out.size()>4096) break; }
  std::wcout << L"OUT_BYTES=" << out.size() << L"\n";
  if (out.find("CONPTY_SMOKE_OK")!=std::string::npos) std::wcout << L"MARKER_OK=1\n"; else std::wcout << L"MARKER_OK=0\n";
  DeleteProcThreadAttributeList(attr); HeapFree(GetProcessHeap(),0,attr);
  closePC(hPC); CloseHandle(inR); CloseHandle(inW); CloseHandle(outR); CloseHandle(outW);
  std::wcout << L"OS_CONPTY_SMOKE=" << (ok && out.find("CONPTY_SMOKE_OK")!=std::string::npos ? L"PASS" : L"FAIL") << L"\n";
  return (ok && out.find("CONPTY_SMOKE_OK")!=std::string::npos) ? 0 : 5;
}
