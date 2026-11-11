#include "DialogBoxWithInput.h"

// Simple stub: uses GetDlgItemText-style input via a basic dialog
// For now, returns false (cancel) so the feature gracefully degrades
bool DialogBoxWithInput(LPCWSTR title, LPCWSTR prompt, LPWSTR buffer, int bufferSize) {
    (void)title;
    (void)prompt;
    (void)buffer;
    (void)bufferSize;
    // Graceful degradation: return cancel so user isn't blocked
    return false;
}
