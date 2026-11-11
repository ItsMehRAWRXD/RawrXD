#include "ide/Clipboard.hpp"
#include <windows.h>

namespace IDE {

bool Clipboard::SetText(const char* text) {
    if (!text) return false;
    
    size_t len = strlen(text) + 1;
    
    // Open clipboard
    if (!OpenClipboard(nullptr)) return false;
    
    // Empty clipboard
    if (!EmptyClipboard()) {
        CloseClipboard();
        return false;
    }
    
    // Allocate global memory
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hMem) {
        CloseClipboard();
        return false;
    }
    
    // Lock and copy text
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    
    memcpy(pMem, text, len);
    GlobalUnlock(hMem);
    
    // Set clipboard data
    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    
    CloseClipboard();
    return true;
}

std::string Clipboard::GetText() {
    std::string result;
    
    if (!OpenClipboard(nullptr)) return result;
    
    // Get clipboard data
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData) {
        char* pText = static_cast<char*>(GlobalLock(hData));
        if (pText) {
            result = pText;
            GlobalUnlock(hData);
        }
    }
    
    CloseClipboard();
    return result;
}

bool Clipboard::HasText() {
    if (!OpenClipboard(nullptr)) return false;
    bool hasText = IsClipboardFormatAvailable(CF_TEXT) || IsClipboardFormatAvailable(CF_UNICODETEXT);
    CloseClipboard();
    return hasText;
}

bool Clipboard::Clear() {
    if (!OpenClipboard(nullptr)) return false;
    bool result = EmptyClipboard();
    CloseClipboard();
    return result;
}

} // namespace IDE
