#include "Win32IDE.h"
#include "Win32IDE_CommandIDs.h"
#include <richedit.h>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int checks = 0;
void Check(bool value, const char* name) {
    if (!value) throw std::runtime_error(name);
    ++checks; std::cout << "PASS " << name << '\n';
}
std::string Text(HWND window) {
    const int length = GetWindowTextLengthA(window);
    std::string text(length + 1, '\0');
    GetWindowTextA(window, text.data(), length + 1); text.resize(length); return text;
}
HWND OwnedDialog(HWND owner, const char* title) {
    for (HWND window = FindWindowA("#32770", title); window;
         window = FindWindowExA(nullptr, window, "#32770", title))
        if (GetWindow(window, GW_OWNER) == owner) return window;
    return nullptr;
}
void Command(HWND window, int command) { SendMessageA(window, WM_COMMAND, command, 0); }
CHARRANGE Selection(HWND editor) {
    CHARRANGE range{}; SendMessageA(editor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&range)); return range;
}
void Click(HWND dialog, int id) {
    HWND button = GetDlgItem(dialog, id);
    SendMessageA(dialog, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED), reinterpret_cast<LPARAM>(button));
}
}
int main() {
    std::cout << std::unitbuf;
    try {
        Win32IDE ide(GetModuleHandleA(nullptr));
        Check(ide.createWindow(), "hidden production window creation");
        HWND main = ide.getMainWindow();
        Check(!IsWindowVisible(main), "main window remains hidden");
        HWND editor = GetDlgItem(main, IDC_EDITOR);
        Check(editor != nullptr, "production RichEdit editor exists");
        char className[64]{}; GetClassNameA(editor, className, sizeof(className));
        Check(std::string(className) == RICHEDIT_CLASSA, "RichEdit selection protocol");
        Check(TabCtrl_GetItemCount(GetDlgItem(main, IDC_DOC_TABS)) == 1, "scratch document tab exists");
        // Seed a clean buffer without generating a user-edit notification.
        SendMessageA(editor, EM_SETEVENTMASK, 0, 0);
        SetWindowTextA(editor, "clean seed");
        Command(main, IDM_FILE_NEW);
        Check(Text(editor).empty(), "canonical File New executes actual handler");
        SendMessageA(editor, EM_SETEVENTMASK, 0, ENM_CHANGE);
        SetWindowTextA(editor, "alpha alphabet ALPHA omega");
        Check(Text(editor) == "alpha alphabet ALPHA omega", "editor notification does not dispatch old overlapping menu IDs");
        SendMessageA(editor, EM_SETSEL, 0, 0);
        Command(main, IDM_EDIT_FIND);
        HWND find = OwnedDialog(main, "Find");
        Check(find != nullptr && !IsWindowVisible(find), "real find dialog created hidden");
        SetDlgItemTextA(find, 5010, "alpha");
        CheckDlgButton(find, 5021, BST_CHECKED);
        Click(find, 5030);
        auto selection = Selection(editor);
        Check(selection.cpMin == 0 && selection.cpMax == 5, "Find Next selects first whole word");
        Command(main, IDM_EDIT_FIND_NEXT);
        selection = Selection(editor);
        Check(selection.cpMin == 15 && selection.cpMax == 20, "menu Find Next skips alphabet and matches uppercase");
        Command(main, IDM_EDIT_FIND_PREV);
        Check(Selection(editor).cpMin == 0, "menu Find Previous routes correctly");
        CheckDlgButton(find, 5020, BST_CHECKED);
        Click(find, 5030);
        Check(Selection(editor).cpMin == 0, "case-sensitive search wraps to matching lowercase word");
        Click(find, 5033);
        Check(!IsWindow(find), "find Close button executes dialog handler");
        Command(main, IDM_EDIT_REPLACE);
        HWND replace = OwnedDialog(main, "Replace");
        Check(replace != nullptr && !IsWindowVisible(replace), "real replace dialog created hidden");
        SetDlgItemTextA(replace, 5010, "alpha");
        SetDlgItemTextA(replace, 5011, "B");
        CheckDlgButton(replace, 5021, BST_CHECKED);
        Click(replace, 5032);
        Check(Text(editor) == "B alphabet B omega", "Replace All preserves inter-match text and boundaries");
        Command(main, IDM_EDIT_UNDO);
        Check(Text(editor) == "alpha alphabet ALPHA omega", "canonical Undo reverses replacement");
        Command(main, IDM_EDIT_REDO);
        Check(Text(editor) == "B alphabet B omega", "canonical Redo restores replacement");
        SetWindowTextA(editor, "id12 id34 x");
        SetDlgItemTextA(replace, 5010, "id([0-9]+)");
        SetDlgItemTextA(replace, 5011, "[$1]");
        CheckDlgButton(replace, 5022, BST_CHECKED);
        CheckDlgButton(replace, 5021, BST_UNCHECKED);
        Click(replace, 5032);
        Check(Text(editor) == "[12] [34] x", "regex replacement expands capture groups without duplicated text");
        SetWindowTextA(editor, "cat cat");
        SendMessageA(editor, EM_SETSEL, 0, 0);
        SetDlgItemTextA(replace, 5010, "cat");
        SetDlgItemTextA(replace, 5011, "dog");
        CheckDlgButton(replace, 5022, BST_UNCHECKED);
        Click(replace, 5030); Click(replace, 5031);
        Check(Text(editor) == "dog cat", "Replace Current mutates exactly selected match");
        Click(replace, 5033);
        Command(main, 2999);
        HWND status = GetDlgItem(main, 1004);
        char statusText[256]{};
        SendMessageA(status, SB_GETTEXTA, 0, reinterpret_cast<LPARAM>(statusText));
        Check(std::string(statusText) == "Unsupported command: 2999", "unknown menu ID reports unsupported");
        // Test menu exit on a recreated clean window so no modal discard prompt is needed.
        DestroyWindow(main);
        Check(!IsWindow(main), "owned window cleanup");
        Win32IDE clean(GetModuleHandleA(nullptr));
        Check(clean.createWindow(), "second hidden production window creation");
        HWND second = clean.getMainWindow();
        Command(second, IDM_FILE_EXIT);
        Check(!IsWindow(second), "canonical File Exit destroys clean window");
        std::cout << "WIN32_COMMAND_DISPATCH_PASS checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WIN32_COMMAND_DISPATCH_FAIL checks=" << checks << " reason=" << error.what() << '\n';
        return 1;
    }
}
