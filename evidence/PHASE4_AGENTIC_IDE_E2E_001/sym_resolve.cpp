#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#pragma comment(lib, "dbghelp.lib")
int wmain(int argc, wchar_t** argv) {
  if (argc < 3) return 1;
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
  HANDLE h = GetCurrentProcess();
  if (!SymInitialize(h, "G:\\~dev\\rawrxd\\evidence\\TIP_FREEZE_001\\bin", FALSE)) return 2;
  DWORD64 base = SymLoadModuleExW(h, NULL, argv[1], NULL, 0x140000000ull, 0, NULL, 0);
  if (!base) base = SymLoadModuleExW(h, NULL, argv[1], NULL, 0, 0, NULL, 0);
  printf("BASE=%llX err=%lu\n", (unsigned long long)base, GetLastError());
  const char* names[] = {
    "?onAgenticModeAsk@Win32IDE@@AEAAXXZ",
    "?onAgenticModePlan@Win32IDE@@AEAAXXZ",
    "?onAgenticModeAgent@Win32IDE@@AEAAXXZ",
    "?setAgenticMode@Win32IDE@@AEAAXW4AgenticMode@RawrXD@@@Z",
    "?HandleAgenticComposerUX@@YAXPEAX@Z",
    "?g_pMainIDE@@3PEAVWin32IDE@@EA",
    NULL
  };
  for (int i=0; names[i]; ++i) {
    char buf[sizeof(SYMBOL_INFO)+512];
    SYMBOL_INFO* s = (SYMBOL_INFO*)buf;
    memset(buf,0,sizeof(buf));
    s->SizeOfStruct = sizeof(SYMBOL_INFO);
    s->MaxNameLen = 500;
    if (SymFromName(h, names[i], s))
      printf("%s ADDR=%llX RVA=%llX\n", names[i], (unsigned long long)s->Address, (unsigned long long)(s->Address - base));
    else
      printf("%s FAIL err=%lu\n", names[i], GetLastError());
  }
  SymCleanup(h);
  return 0;
}
