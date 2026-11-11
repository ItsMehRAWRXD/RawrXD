#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include <mutex>
#include <atomic>
#include "../../../src/win32app/Win32TerminalManager.h"

static std::mutex g_mu;
static std::string g_out;

static bool wait_for(const char* needle, DWORD ms) {
  DWORD t0 = GetTickCount();
  for (;;) {
    {
      std::lock_guard<std::mutex> lk(g_mu);
      if (g_out.find(needle) != std::string::npos) return true;
    }
    if (GetTickCount() - t0 > ms) return false;
    Sleep(40);
  }
}

int main() {
  SetConsoleOutputCP(CP_UTF8);
  // Isolate parent console so child ConPTY I/O does not attach here.
  FreeConsole();
  FILE* out = nullptr;
  fopen_s(&out,
          "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\logs\\conpty_capture_run.txt",
          "wb");
  if (!out) return 99;
  auto emit = [&](const char* line) {
    fputs(line, out);
    fputc('\n', out);
    fflush(out);
  };
  emit("terminal_conpty_capture PROMOTE=0");

  Win32TerminalManager tm;
  tm.onOutput = [](const std::string& s) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_out += s;
  };
  if (!tm.start(Win32TerminalManager::PowerShell)) {
    char buf[64];
    snprintf(buf, sizeof(buf), "FAIL start\nTRANSPORT=%d", (int)tm.transport());
    emit(buf);
    fclose(out);
    return 2;
  }
  const int transport = (int)tm.transport();
  {
    char buf[128];
    snprintf(buf, sizeof(buf), "TRANSPORT=%d pid=%lu", transport,
             (unsigned long)tm.pid());
    emit(buf);
  }
  if (transport != Win32TerminalManager::TransportConPTY) {
    emit("CONPTY_PRODUCT_WIRED=0");
    emit("TERMINAL_CAPTURE=FAIL_CLOSED");
    emit("PROMOTE=0");
    tm.stop();
    fclose(out);
    return 3;
  }
  emit("CONPTY_PRODUCT_WIRED=1");
  wait_for("PS ", 5000);
  Sleep(400);
  tm.writeInput("Write-Output 'CONPTY_MARK_F15'\r\n");
  int hit = wait_for("CONPTY_MARK_F15", 15000) ? 1 : 0;
  {
    char buf[128];
    snprintf(buf, sizeof(buf), "CAPTURE_HAS_MARK=%d OUT_LEN=%zu", hit, g_out.size());
    emit(buf);
  }
  if (!hit) {
    std::lock_guard<std::mutex> lk(g_mu);
    fputs("OUT_HEX_HEAD=", out);
    size_t n = g_out.size() < 96 ? g_out.size() : 96;
    for (size_t i = 0; i < n; i++)
      fprintf(out, "%02X", (unsigned char)g_out[i]);
    fputc('\n', out);
  }
  tm.stop();
  emit(hit ? "TERMINAL_CAPTURE=PASS" : "TERMINAL_CAPTURE=FAIL_CLOSED");
  emit("PROMOTE=0");
  fclose(out);
  return hit ? 0 : 1;
}
