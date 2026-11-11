#include <windows.h>
#include <stdio.h>
#include <stdint.h>
typedef int (*LockstepNet_Init_t)(uint16_t, uint32_t, uint16_t);
typedef int (*LockstepNet_Shutdown_t)(void);
int main(){
  HMODULE h=LoadLibraryA("d:\\rawrxd-ci-bootstrap\\Sovereign_SDK.patched.dll");
  if(!h){ printf("load fail err=%lu\n", GetLastError()); return 1; }
  auto init=(LockstepNet_Init_t)GetProcAddress(h,"LockstepNet_Init");
  auto shut=(LockstepNet_Shutdown_t)GetProcAddress(h,"LockstepNet_Shutdown");
  printf("init=%p shut=%p\n", (void*)init, (void*)shut);
  int ok=-1;
  __try { ok = init(7797, 0x0100007Fu, 7798); printf("init ret=%d\n", ok); }
  __except(EXCEPTION_EXECUTE_HANDLER) { printf("init AV code=0x%08lX\n", GetExceptionCode()); }
  if(shut){ __try { printf("shutdown ret=%d\n", shut()); } __except(EXCEPTION_EXECUTE_HANDLER){ printf("shutdown AV code=0x%08lX\n", GetExceptionCode()); }}
  FreeLibrary(h);
  return 0;
}
