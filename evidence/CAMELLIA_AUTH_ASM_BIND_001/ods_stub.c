/* Harness-only: Auth/Camellia ASM calls OutputDebugStringA with RSP%16!=0
 * (set_key: 8 pushes + sub rsp,64 => RSP%16==8 before call). That AVs inside
 * kernelbase. Provide a local no-op and link with /FORCE:MULTIPLE so the smoke
 * can exercise RCM2 without patching product ASM or rebuilding Win32IDE. */
#include <windows.h>
void OutputDebugStringA(LPCSTR lpOutputString) {
    (void)lpOutputString;
}
