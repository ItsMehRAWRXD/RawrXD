#include <windows.h>
#include <stdio.h>
int main(void) {
  const char* names[] = {"amdhip64.dll","amdhip64_6.dll","hiprt64.dll",0};
  for (int i=0; names[i]; ++i) {
    HMODULE h = LoadLibraryA(names[i]);
    printf("%s load=%d err=%lu\n", names[i], h!=NULL, h?0:GetLastError());
    if (h) {
      FARPROC p = GetProcAddress(h, "hipInit");
      printf("  hipInit=%d\n", p!=NULL);
      if (p) { typedef int (*PFN)(unsigned); printf("  hipInit_rc=%d\n", ((PFN)p)(0)); }
      FARPROC dc = GetProcAddress(h, "hipGetDeviceCount");
      printf("  hipGetDeviceCount=%d\n", dc!=NULL);
      if (dc) { typedef int (*PFN2)(int*); int n=-1; int rc=((PFN2)dc)(&n); printf("  devcount_rc=%d n=%d\n", rc, n); }
      FreeLibrary(h);
    }
  }
  return 0;
}
