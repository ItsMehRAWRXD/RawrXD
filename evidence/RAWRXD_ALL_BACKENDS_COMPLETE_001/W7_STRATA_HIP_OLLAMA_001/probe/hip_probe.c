#include <windows.h>
#include <stdio.h>
int main(void) {
  HMODULE h = LoadLibraryA("amdhip64.dll");
  printf("amdhip64_load=%d\n", h != NULL);
  if (!h) { printf("err=%lu\n", GetLastError()); return 1; }
  FARPROC p = GetProcAddress(h, "hipInit");
  printf("hipInit_sym=%d\n", p != NULL);
  if (p) {
    typedef int (*PFN)(unsigned);
    int rc = ((PFN)p)(0);
    printf("hipInit_rc=%d\n", rc);
  }
  FreeLibrary(h);
  return 0;
}
