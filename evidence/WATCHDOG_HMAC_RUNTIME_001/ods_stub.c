/* Harness-only: Camellia ASM may call OutputDebugStringA with RSP%%16!=0.
 * Link with /FORCE:MULTIPLE so smoke can exercise get_hmac_key without AV. */
#include <windows.h>
void OutputDebugStringA(LPCSTR lpOutputString) {
    (void)lpOutputString;
}
