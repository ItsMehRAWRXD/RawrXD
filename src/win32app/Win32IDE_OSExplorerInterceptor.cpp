#include "Win32IDE.h"
#include <windows.h>

// Product path: OSExplorerInterceptor remains FEATURE_FICTION on tip.
// Do not ShellExecute from this entry — CommandResult overload already
// returns exit 1; keep void* dispatch fail-closed the same way.
void HandleOSExplorerInterceptor(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    const char* msg =
        "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 OSExplorerInterceptor\n";
    if (ide) {
        ide->appendToOutput(msg, "Explorer", Win32IDE::OutputSeverity::Error);
    }
}
