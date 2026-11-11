#include "Win32IDE_CodexCommands.h"
#include "Win32IDE.h"
#include "Win32IDE_CommandIDs.h"
#include <richedit.h>
#include <cstring>

namespace {
std::string selectedText(HWND editor) {
    if (!editor) return {};
    CHARRANGE range{}; SendMessageA(editor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&range));
    if (range.cpMax <= range.cpMin) return {};
    TEXTRANGEA tr{}; tr.chrg = range;
    std::string text(static_cast<size_t>(range.cpMax - range.cpMin) + 1, '\0');
    tr.lpstrText = text.data();
    SendMessageA(editor, EM_GETTEXTRANGE, 0, reinterpret_cast<LPARAM>(&tr));
    text.resize(std::strlen(text.c_str())); return text;
}
void runPrompt(Win32IDE& ide, const char* action) {
    ide.runNativeCodexPrompt(std::string(action) + " this code. Return the result and concise explanation:\n" + selectedText(ide.editorHandle()));
}
}

void RegisterNativeCodexCommands(Win32IDE& ide) {
    ide.registerCommandHandler(IDM_CODEX_COMPLETE, [&ide]{ runPrompt(ide, "Complete"); });
    ide.registerCommandHandler(IDM_CODEX_EXPLAIN, [&ide]{ runPrompt(ide, "Explain"); });
    ide.registerCommandHandler(IDM_CODEX_REFACTOR, [&ide]{ runPrompt(ide, "Refactor"); });
    ide.registerCommandHandler(IDM_CODEX_FIX, [&ide]{ runPrompt(ide, "Fix"); });
}
