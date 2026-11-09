#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>

// FOUR_PANEL Track J — determine native debug backend without inventing PASS.
// Product backend: NativeDebuggerEngine (DbgEng COM) via Win32IDE_NativeDebugPanel.
// This probe verifies dbgeng.dll load + fixture compile; full BP E2E needs IDE relink.

int main() {
  printf("DEBUG_CONSOLE_GATE probe PROMOTE=0\n");
  HMODULE h = LoadLibraryA("dbgeng.dll");
  printf("DBGENG_DLL=%d\n", h?1:0);
  if (!h) {
    printf("DEBUG_CONSOLE=FAIL_CLOSED\n");
    printf("MISSING_BACKEND=dbgeng.dll_not_loadable\n");
    printf("REQUIRED=launch,attach,breakpoints,continue/pause/stop/restart,step,stack,vars,exceptions,I/O,UI_nonblock\n");
    return 2;
  }
  FreeLibrary(h);
  printf("SOURCE_BACKEND=NativeDebuggerEngine(DbgEng)\n");
  printf("PRODUCT_UI=Win32IDE_NativeDebugPanel.cpp + Win32IDE_Debugger*.cpp\n");
  printf("NOTE=Harness confirms dbgeng presence; HWND BP/step E2E requires candidate IDE EXE relink+run\n");
  printf("DEBUG_CONSOLE=RUNTIME_PARTIAL\n");
  printf("PROMOTE=0 TIP_CLIMB=HOLD NOT_RUN!=PASS\n");
  return 0;
}