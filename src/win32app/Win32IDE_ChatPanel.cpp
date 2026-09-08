#include "Win32IDE.h"
#include <windows.h>

void HandleChatPanel(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;
    ide->createChatPanel();
    if (ide->getMainWindow()) {
        ide->appendToOutput("[ChatPanel] createChatPanel invoked\n", "Chat",
                            Win32IDE::OutputSeverity::Info);
    }
}
