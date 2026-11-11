#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <iostream>
#include <atomic>
#include <thread>
#include <chrono>
#include <fstream>
#include <mutex>
#include <vector>
#include <functional>
// Minimal reimplementation of pipe-shell contract matching Win32TerminalManager surface for gate measurement.
static std::mutex g_mu;
static std::string g_out, g_err;
static std::atomic<bool> g_running{false};
static HANDLE g_proc=nullptr; static DWORD g_pid=0;
static HANDLE g_inW=nullptr, g_outR=nullptr, g_errR=nullptr;
static void reader(HANDLE h, std::string* dest){
  char buf[512]; DWORD n=0;
  while(g_running && ReadFile(h,buf,sizeof(buf),&n,nullptr) && n>0){
    std::lock_guard<std::mutex> lk(g_mu); dest->append(buf,buf+n);
  }
}
static bool start_ps(){
  SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
  HANDLE outW=nullptr, errW=nullptr, inR=nullptr;
  if(!CreatePipe(&g_outR,&outW,&sa,0)||!CreatePipe(&g_errR,&errW,&sa,0)||!CreatePipe(&inR,&g_inW,&sa,0)) return false;
  SetHandleInformation(g_outR,HANDLE_FLAG_INHERIT,0);
  SetHandleInformation(g_errR,HANDLE_FLAG_INHERIT,0);
  SetHandleInformation(g_inW,HANDLE_FLAG_INHERIT,0);
  STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES; si.hStdInput=inR; si.hStdOutput=outW; si.hStdError=errW;
  PROCESS_INFORMATION pi{};
  wchar_t cmd[]=L"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command -";
  if(!CreateProcessW(nullptr,cmd,nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)) return false;
  CloseHandle(outW); CloseHandle(errW); CloseHandle(inR); CloseHandle(pi.hThread);
  g_proc=pi.hProcess; g_pid=pi.dwProcessId; g_running=true;
  std::thread(reader,g_outR,&g_out).detach();
  std::thread(reader,g_errR,&g_err).detach();
  return true;
}
static bool write_line(const std::string& s){
  DWORD n=0; std::string t=s+"\n"; return WriteFile(g_inW,t.data(),(DWORD)t.size(),&n,nullptr)!=0;
}
static void stop_kill(){
  g_running=false;
  if(g_proc){ TerminateProcess(g_proc,1); WaitForSingleObject(g_proc,5000); CloseHandle(g_proc); g_proc=nullptr; }
}
int main(){
  std::ofstream rec("F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\logs\\terminal_probe_receipt.txt");
  auto log=[&](const std::string&k,const std::string&v){ rec<<k<<"="<<v<<"\n"; std::cout<<k<<"="<<v<<"\n"; };
  // Detect ConPTY availability in OS (not product wiring)
  HMODULE k32=GetModuleHandleW(L"kernel32.dll");
  auto pCreate=(void*)GetProcAddress(k32,"CreatePseudoConsole");
  log("OS_CREATEPSEUDOCONSOLE", pCreate?"PRESENT":"ABSENT");
  log("PRODUCT_A4F_CREATEPSEUDOCONSOLE_STRING","0"); // measured earlier
  log("TRANSPORT","PIPE_REDIRECT_CreateProcess");
  if(!start_ps()){ log("START","FAIL"); return 2; }
  log("START","PASS"); log("PID",std::to_string(g_pid));
  // compile real C++ from shell
  write_line("$code=@'\n#include <stdio.h>\nint main(){puts(\"ONESHOT_TERM_HELLO\");return 0;}\n'@; Set-Content -Path F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.c -Value $code -Encoding ASCII");
  write_line("& \"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.44.35207\\bin\\Hostx64\\x64\\cl.exe\" /nologo /Fe:F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.exe F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.c");
  write_line("F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\term_hello.exe");
  write_line("Write-Output TERM_EXIT_$LASTEXITCODE");
  Sleep(8000);
  { std::lock_guard<std::mutex> lk(g_mu); log("STDOUT_HAS_HELLO", g_out.find("ONESHOT_TERM_HELLO")!=std::string::npos?"1":"0"); log("STDOUT_LEN",std::to_string(g_out.size())); }
  // cancel long command
  write_line("Start-Sleep -Seconds 60");
  Sleep(1000);
  // Ctrl+C analogue: kill process tree via taskkill /T
  std::string kill="taskkill /PID "+std::to_string(g_pid)+" /T /F";
  system(kill.c_str());
  Sleep(1500);
  DWORD ec=0; GetExitCodeProcess(g_proc,&ec);
  log("CANCEL_EXITCODE", std::to_string(ec));
  // orphan check
  // restart
  stop_kill();
  bool restart=start_ps();
  log("RESTART", restart?"PASS":"FAIL");
  if(restart){ write_line("Write-Output RESTARTED_OK"); Sleep(2000); std::lock_guard<std::mutex> lk(g_mu); log("RESTART_OUT", g_out.find("RESTARTED_OK")!=std::string::npos?"1":"0"); }
  stop_kill();
  // orphan residual powershell children from this probe - best effort
  log("CONPTY_PRODUCT_WIRED","0");
  log("FULL_INTERACTIVE_CONPTY","FAIL");
  log("PIPE_SUBPROCESS_COMPILE_RUN", (g_out.find("ONESHOT_TERM_HELLO")!=std::string::npos)?"PASS":"FAIL");
  return 0;
}
