#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include <atomic>
#include <mutex>
#include "g:/~dev/rawrxd/src/win32app/Win32TerminalManager.h"

static std::mutex g_mu;
static std::string g_out;
static std::atomic<int> g_exit{-1};

static void bind(Win32TerminalManager& tm) {
  tm.onOutput = [](const std::string& s) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_out += s;
  };
  tm.onFinished = [](int c) { g_exit = c; };
}

static int orphan_gone(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return 1;
  DWORD code = 0;
  GetExitCodeProcess(h, &code);
  CloseHandle(h);
  return code != STILL_ACTIVE;
}

int main() {
  printf("CONPTY_STOP_HARNESS_PRIV_R94 PROMOTE=0 CROSS_SHA=0\n");
  fflush(stdout);
  int fail = 0;
  for (int i = 0; i < 3; i++) {
    g_out.clear();
    g_exit = -1;
    Win32TerminalManager tm;
    bind(tm);
    wchar_t cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    tm.setWorkingDirectory(cwd);
    if (!tm.start(Win32TerminalManager::CommandPrompt)) {
      printf("FAIL start iter=%d\n", i);
      fail++;
      continue;
    }
    Sleep(300);
    tm.writeInput("echo CONPTY_STOP_MARK_R94\r\n");
    Sleep(500);
    int out_ok = 0;
    {
      std::lock_guard<std::mutex> lk(g_mu);
      out_ok = (g_out.find("CONPTY_STOP_MARK_R94") != std::string::npos) ? 1 : 0;
    }
    DWORD pid = tm.pid();
    DWORD tStop0 = GetTickCount();
    tm.stop();
    DWORD stopMs = GetTickCount() - tStop0;
    int gone = orphan_gone(pid);
    int hang = stopMs > 8000 ? 1 : 0;
    printf("ITER=%d START=1 OUT_OK=%d STOP_MS=%lu ORPHAN_GONE=%d HANG=%d\n", i,
           out_ok, (unsigned long)stopMs, gone, hang);
    if (!out_ok) {
      printf("FAIL output iter=%d\n", i);
      fail++;
    }
    if (!gone) {
      printf("FAIL orphan iter=%d pid=%lu\n", i, (unsigned long)pid);
      fail++;
    }
    if (hang) {
      printf("FAIL stop_hang iter=%d ms=%lu\n", i, (unsigned long)stopMs);
      fail++;
    } else if (gone && out_ok) {
      printf("PASS start_output_stop_cleanup iter=%d\n", i);
    }
  }
  printf("RESULT=%s fail_count=%d\n", fail ? "FAIL" : "PASS", fail);
  return fail ? 1 : 0;
}
