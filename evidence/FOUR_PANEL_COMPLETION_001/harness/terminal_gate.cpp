#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include <atomic>
#include <mutex>
#include "../../../src/win32app/Win32TerminalManager.h"

static std::mutex g_mu;
static std::string g_out;
static std::atomic<int> g_exit{-1};

static std::string strip_ansi(std::string s) {
  std::string o; o.reserve(s.size());
  for (size_t i=0;i<s.size();) {
    if (s[i]=='\x1b') {
      if (i+1<s.size() && s[i+1]=='[') {
        i+=2; while (i<s.size() && !(s[i]>='@'&&s[i]<='~')) i++;
        if (i<s.size()) i++; continue;
      }
      if (i+1<s.size() && s[i+1]==']') { // OSC
        i+=2; while (i<s.size() && s[i]!='\x07' && !(s[i]=='\x1b'&&i+1<s.size()&&s[i+1]=='\\')) i++;
        if (i<s.size() && s[i]=='\x07') i++;
        else if (i+1<s.size()) i+=2;
        continue;
      }
    }
    o.push_back(s[i++]);
  }
  return o;
}

static void bind(Win32TerminalManager& tm) {
  tm.onOutput = [](const std::string& s) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_out += s;
  };
  tm.onFinished = [](int c) { g_exit = c; };
}

static bool wait_for(const char* needle, DWORD ms) {
  DWORD t0 = GetTickCount();
  for (;;) {
    {
      std::lock_guard<std::mutex> lk(g_mu);
      if (strip_ansi(g_out).find(needle) != std::string::npos) return true;
    }
    if (GetTickCount() - t0 > ms) return false;
    Sleep(40);
  }
}

static int orphan_gone(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return 1;
  DWORD code=0; GetExitCodeProcess(h,&code); CloseHandle(h);
  return code != STILL_ACTIVE;
}

int main() {
  int fail=0;
  SetConsoleOutputCP(CP_UTF8);
  printf("TERMINAL_GATE harness v4 PROMOTE=0\n");
  fflush(stdout);

  {
    g_out.clear(); g_exit=-1;
    Win32TerminalManager tm; bind(tm);
    wchar_t cwd[MAX_PATH]; GetCurrentDirectoryW(MAX_PATH,cwd);
    tm.setWorkingDirectory(cwd);
    if (!tm.start(Win32TerminalManager::CommandPrompt)) {
      printf("FAIL CreatePseudoConsole/start\n"); return 2;
    }
    Sleep(500);
    tm.writeInput("echo CONPTY_MARK_A7F3\r\n");
    if (wait_for("CONPTY_MARK_A7F3", 12000)) printf("PASS echo capture marker_in_pipe\n");
    else {
      printf("FAIL echo capture\n");
      std::lock_guard<std::mutex> lk(g_mu);
      auto plain = strip_ansi(g_out);
      printf("DUMP_LEN=%zu TAIL=%.240s\n", plain.size(),
             plain.size()>240?plain.c_str()+plain.size()-240:plain.c_str());
      fail++;
    }

    tm.writeInput("cl /nologo /EHsc /Fe:bin\\fixed_via_term.exe fixtures\\fixed.cpp\r\n");
    Sleep(3000);
    tm.writeInput("bin\\fixed_via_term.exe\r\n");
    if (wait_for("FIXED_OK", 20000)) printf("PASS compile+run via ConPTY\n");
    else { printf("FAIL compile+run via ConPTY\n"); fail++; }

    tm.writeInput("ping -n 20 127.0.0.1 >nul\r\n");
    Sleep(400);
    tm.interrupt();
    Sleep(400);
    printf("PASS interrupt issued\n");

    if (tm.resize(120, 35)) printf("PASS resize\n"); else { printf("FAIL resize\n"); fail++; }

    DWORD pid = tm.pid();
    if (tm.restart()) printf("PASS restart\n"); else { printf("FAIL restart\n"); fail++; }
    Sleep(500);
    tm.writeInput("echo CONPTY_MARK_RESTART\r\n");
    if (wait_for("CONPTY_MARK_RESTART", 10000)) printf("PASS capture after restart\n");
    else { printf("FAIL capture after restart\n"); fail++; }

    tm.stop();
    Sleep(400);
    if (orphan_gone(pid)) printf("PASS no orphan after stop\n");
    else { printf("FAIL orphan pid %lu\n", (unsigned long)pid); fail++; }
  }

  {
    g_out.clear();
    Win32TerminalManager tm; bind(tm);
    if (!tm.start(Win32TerminalManager::PowerShell)) {
      printf("FAIL PowerShell start\n"); fail++;
    } else {
      Sleep(800);
      tm.writeInput("Write-Output 'PS_MARK_B91'\r\n");
      if (wait_for("PS_MARK_B91", 15000)) printf("PASS PowerShell capture\n");
      else { printf("FAIL PowerShell capture\n"); fail++; }
      tm.stop();
    }
  }

  printf("TERMINAL_GATE fail_count=%d\n", fail);
  printf("TERMINAL=%s\n", fail ? "FAIL_CLOSED" : "PASS");
  printf("PROMOTE=0 TIP_CLIMB=HOLD\n");
  fflush(stdout);
  return fail ? 1 : 0;
}