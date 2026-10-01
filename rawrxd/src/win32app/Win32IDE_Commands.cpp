// ============================================================================
// Win32IDE_Commands.cpp ? Full menu command router wired to EditorEngine + TabManager + FileOps
// Production: Open/Save/Close using real APIs, multi-document tab tracking, find/replace.
// ============================================================================
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <algorithm>
#include <cstdio>
#include <sstream>

#pragma comment(lib, "comdlg32.lib")

namespace RawrXD::IDE {
    std::string FileOps_OpenDialog(HWND parent, const std::string& filter);
    std::string FileOps_SaveDialog(HWND parent, const std::string& defaultName, const std::string& filter);
    bool        FileOps_Exists(const std::string& path);
    std::string FileOps_GetDirectory(const std::string& path);
    std::string FileOps_GetFilename(const std::string& path);

    bool        EditorEngine_OpenFile(const std::string& path);
    bool        EditorEngine_SaveFile(const std::string& path);
    void        EditorEngine_SetText(const std::string& text);
    std::string EditorEngine_GetText();
    void        EditorEngine_AppendText(const std::string& text);
    void        EditorEngine_InsertTextAtCursor(const std::string& text);
    bool        EditorEngine_IsModified();
    const std::string& EditorEngine_FilePath();
    void        EditorEngine_SelectAll();
    bool        EditorEngine_Find(const std::string& what, bool matchCase);
    bool        EditorEngine_Replace(const std::string& what, const std::string& replacement, bool matchCase);
    int         EditorEngine_ReplaceAll(const std::string& what, const std::string& replacement, bool matchCase);
    bool        EditorEngine_HasSelection();
    std::string EditorEngine_GetSelectionText();
    bool        EditorEngine_DeleteSelection();
    void        EditorEngine_GetCaret(int* line, int* col);
    void        EditorEngine_SetCaret(int line, int col);
    void        EditorEngine_RegisterMutationHook(void (*fn)());

    void        TabManager_OpenFile(const std::string& path);
    void        TabManager_SetModified(const std::string& path, bool modified);
    std::string TabManager_ActivePath();
    std::vector<std::string> TabManager_OpenPaths();
    bool        TabManager_IsModified(const std::string& path);
    size_t      TabManager_Count();

    // RAWRXD_IDE_SETTINGS_WIRING_001: defined in Win32IDE_SettingsGUI.cpp.
    // It had zero callers, and it also passed a NULL dialog template, so all 13
    // settings controls were both unreachable and unshowable.
    void        SettingsGUI_Show(HWND parent);
}

namespace {

static HWND g_hwndMain = nullptr;

static std::unordered_map<int, std::function<void()>> g_commandHandlers;
static std::vector<std::string> g_recentFiles;
static bool g_dirty = false;

// Undo stack for EditorEngine (line-level snapshots)
static std::vector<std::vector<std::string>> g_undoStack;
static int g_undoPos = -1;

constexpr int IDM_FILE_NEW    = 1001;
constexpr int IDM_FILE_OPEN   = 1002;
constexpr int IDM_FILE_SAVE   = 1003;
constexpr int IDM_FILE_SAVEAS = 1004;
constexpr int IDM_FILE_SAVEALL= 1005;
constexpr int IDM_FILE_CLOSE  = 1006;
// RAWRXD_IDE_SETTINGS_WIRING_001
// SettingsGUI_Show() had zero callers, so all 13 settings controls (font size,
// tab size, word wrap, line numbers, autosave, LSP/MCP configuration, theme,
// minimap) were unreachable from the product.
constexpr int IDM_FILE_SETTINGS= 1007;
constexpr int IDM_FILE_RECENT_BASE = 1010;
constexpr int IDM_FILE_RECENT_CLEAR= 1020;
constexpr int IDM_FILE_EXIT   = 1099;

// Edit commands renumbered to avoid collision with IDM_BUILD_NATIVE=2001
constexpr int IDM_EDIT_UNDO        = 2101;
constexpr int IDM_EDIT_REDO        = 2102;
constexpr int IDM_EDIT_CUT         = 2103;
constexpr int IDM_EDIT_COPY        = 2104;
constexpr int IDM_EDIT_PASTE       = 2105;
constexpr int IDM_EDIT_SELECT_ALL  = 2106;
constexpr int IDM_EDIT_FIND        = 2107;
constexpr int IDM_EDIT_FINDNEXT    = 2109;
constexpr int IDM_EDIT_REPLACE     = 2108;
constexpr int IDM_EDIT_REPLACEALL  = 2110;

static void SnapshotForUndo() {
    using namespace RawrXD::IDE;
    std::string txt = EditorEngine_GetText();
    std::vector<std::string> lines;
    std::istringstream ss(txt);
    std::string ln;
    while (std::getline(ss, ln)) {
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
        lines.push_back(ln);
    }
    // Discard redo history beyond current position
    if (g_undoPos + 1 < (int)g_undoStack.size()) {
        g_undoStack.resize(g_undoPos + 1);
    }
    g_undoStack.push_back(lines);
    if (g_undoStack.size() > 50) { // limit depth
        g_undoStack.erase(g_undoStack.begin());
    } else {
        ++g_undoPos;
    }
}

// RAWRXD_IDE_UNDO_COVERAGE_001
// The editor fires this hook after a debounce window closes on a keystroke
// burst, so typing now produces undo steps. Before this, the only callers of
// SnapshotForUndo were DoEditCut and DoEditPaste, so a single Ctrl+Z after
// typing reverted the entire buffer to the file-open snapshot.
static void OnEditorMutation() { SnapshotForUndo(); }

static void ResetUndoHistory() {
    g_undoStack.clear();
    g_undoPos = -1;
    SnapshotForUndo();
}

static void PushInitialSnapshot() {
    using namespace RawrXD::IDE;
    if (g_undoStack.empty()) SnapshotForUndo();
}

static void UpdateTitle() {
    if (!g_hwndMain) return;
    using namespace RawrXD::IDE;
    std::wstring title = L"RawrXD Win32IDE";
    std::string path = EditorEngine_FilePath();
    if (!path.empty()) {
        std::string name = FileOps_GetFilename(path);
        int wlen = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
        std::wstring wname(wlen - 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, wname.data(), wlen);
        title += L" - " + wname;
    }
    if (EditorEngine_IsModified()) title += L" *";
    SetWindowTextW(g_hwndMain, title.c_str());
}

static void AddToRecent(const std::string& path) {
    auto it = std::find(g_recentFiles.begin(), g_recentFiles.end(), path);
    if (it != g_recentFiles.end()) g_recentFiles.erase(it);
    g_recentFiles.insert(g_recentFiles.begin(), path);
    if (g_recentFiles.size() > 10) g_recentFiles.resize(10);
}

// Returns false when the user cancelled the unsaved-changes prompt, so callers
// (notably File -> Close) do not clear the document behind a cancelled save.
static bool DoFileNew() {
    using namespace RawrXD::IDE;
    if (EditorEngine_IsModified()) {
        int r = MessageBoxW(g_hwndMain, L"Save changes before closing?", L"Unsaved Changes", MB_YESNOCANCEL);
        if (r == IDCANCEL) return false;
        if (r == IDYES) {
            std::string p = EditorEngine_FilePath();
            if (p.empty()) {
                p = FileOps_SaveDialog(g_hwndMain, "", "All Files\0*.*\0C/C++ Files\0*.c;*.cpp;*.h;*.hpp\0");
                if (p.empty()) return false;
            }
            EditorEngine_SaveFile(p);
            TabManager_SetModified(p, false);
        }
    }
    EditorEngine_SetText("");
    UpdateTitle();
    return true;
}

static void DoFileOpen() {
    using namespace RawrXD::IDE;
    std::string path = FileOps_OpenDialog(g_hwndMain, "All Files\0*.*\0C/C++ Files\0*.c;*.cpp;*.h;*.hpp\0");
    if (!path.empty()) {
        TabManager_OpenFile(path);
        AddToRecent(path);
        UpdateTitle();
        PushInitialSnapshot();
    }
}

static void DoFileSaveAs();

static void DoFileSave() {
    using namespace RawrXD::IDE;
    std::string path = EditorEngine_FilePath();
    if (path.empty()) { DoFileSaveAs(); return; }
    if (EditorEngine_SaveFile(path)) {
        TabManager_SetModified(path, false);
        UpdateTitle();
    }
}

static void DoFileSaveAs() {
    using namespace RawrXD::IDE;
    std::string path = FileOps_SaveDialog(g_hwndMain, EditorEngine_FilePath(), "All Files\0*.*\0C/C++ Files\0*.c;*.cpp;*.h;*.hpp\0");
    if (!path.empty()) {
        if (EditorEngine_SaveFile(path)) {
            TabManager_SetModified(path, false);
            UpdateTitle();
        }
    }
}

// RAWRXD_IDE_SAVEALL_CLOSE_001
// Both of these were aliases that silently did something else: Save All called
// DoFileSave() and Close called DoFileNew(). The tab manager is the source of
// truth for what is open, so iterate it instead of pretending.
static void DoFileSaveAll() {
    using namespace RawrXD::IDE;
    std::string active = EditorEngine_FilePath();
    if (!active.empty() && EditorEngine_IsModified()) {
        EditorEngine_SaveFile(active);
        TabManager_SetModified(active, false);
    }
    for (const std::string& p : TabManager_OpenPaths()) {
        if (p == active) continue;
        if (TabManager_IsModified(p)) {
            if (EditorEngine_SaveFile(p)) TabManager_SetModified(p, false);
        }
    }
    UpdateTitle();
}

static void DoFileClose() {
    using namespace RawrXD::IDE;
    // Ask first, then clear, exactly as New does, but keep the undo history
    // scoped to the new empty document instead of leaking the old one.
    if (!DoFileNew()) return;
    ResetUndoHistory();
}

static void DoFileExit() { PostMessage(g_hwndMain, WM_CLOSE, 0, 0); }

// RAWRXD_IDE_UNDO_CARET_001
// Undo used to restore text with the caret collapsed to 0,0, so the user had to
// re-find their position after every Ctrl+Z. Clamp the caret against the
// restored buffer instead of discarding it.
static void RestoreSnapshot(int idx) {
    using namespace RawrXD::IDE;
    std::string txt;
    for (size_t i = 0; i < g_undoStack[idx].size(); ++i) {
        txt += g_undoStack[idx][i];
        if (i + 1 < g_undoStack[idx].size()) txt += "\n";
    }
    int cl = 0, cc = 0;
    EditorEngine_GetCaret(&cl, &cc);
    EditorEngine_SetText(txt);
    EditorEngine_SetCaret(cl, cc);
    UpdateTitle();
}

static void DoEditUndo() {
    if (g_undoPos > 0) {
        --g_undoPos;
        RestoreSnapshot(g_undoPos);
    }
}

static void DoEditRedo() {
    if (g_undoPos + 1 < (int)g_undoStack.size()) {
        ++g_undoPos;
        RestoreSnapshot(g_undoPos);
    }
}

// RAWRXD_IDE_CLIPBOARD_UNICODE_001
// CF_TEXT is ANSI, so any non-ASCII character pasted through the IDE was
// transcoded through the active code page and came back as mojibake. Publish
// and consume CF_UNICODETEXT, converting through UTF-8 so the round trip is
// byte-exact.
static void ClipboardSetText(const std::string& utf8) {
    if (!utf8.empty() && OpenClipboard(g_hwndMain)) {
        EmptyClipboard();
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        if (wlen > 1) {
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, wlen * sizeof(wchar_t));
            if (hMem) {
                wchar_t* wp = (wchar_t*)GlobalLock(hMem);
                MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wp, wlen);
                GlobalUnlock(hMem);
                SetClipboardData(CF_UNICODETEXT, hMem);
            }
        }
        CloseClipboard();
    }
}

// Returns false when the clipboard holds neither Unicode nor ANSI text.
static bool ClipboardGetText(std::string* out) {
    if (!OpenClipboard(g_hwndMain)) return false;
    bool got = false;
    if (HANDLE hUni = GetClipboardData(CF_UNICODETEXT)) {
        const wchar_t* wp = (const wchar_t*)GlobalLock(hUni);
        if (wp) {
            int need = WideCharToMultiByte(CP_UTF8, 0, wp, -1, nullptr, 0, nullptr, nullptr);
            if (need > 1) {
                std::string buf(need - 1, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wp, -1, buf.data(), need, nullptr, nullptr);
                *out = buf;
                got = true;
            }
            GlobalUnlock(hUni);
        }
    }
    if (!got) {
        if (HANDLE hAnsi = GetClipboardData(CF_TEXT)) {
            const char* ap = (const char*)GlobalLock(hAnsi);
            if (ap) { *out = ap; got = true; }
            GlobalUnlock(hAnsi);
        }
    }
    CloseClipboard();
    return got;
}

// RAWRXD_IDE_CLIPBOARD_SELECTION_001
// Cut/Copy/Paste previously operated on the whole buffer unconditionally:
// Copy ignored the selection entirely, and Cut cleared the entire document
// after putting the whole document on the clipboard. They now act on the
// selection, falling back to the whole buffer only when nothing is selected.
static std::string ClipboardTarget() {
    using namespace RawrXD::IDE;
    if (EditorEngine_HasSelection()) return EditorEngine_GetSelectionText();
    return EditorEngine_GetText();
}

static void DoEditCut() {
    using namespace RawrXD::IDE;
    SnapshotForUndo();
    std::string txt = ClipboardTarget();
    if (txt.empty()) return;
    ClipboardSetText(txt);
    // Cut must not silently widen to "delete everything" when there is no
    // selection: without a selection there is nothing to cut.
    if (EditorEngine_HasSelection()) {
        EditorEngine_DeleteSelection();
    }
    UpdateTitle();
}

static void DoEditCopy() {
    std::string txt = ClipboardTarget();
    if (!txt.empty()) ClipboardSetText(txt);
}

static void DoEditPaste() {
    using namespace RawrXD::IDE;
    SnapshotForUndo();
    std::string txt;
    if (!ClipboardGetText(&txt) || txt.empty()) return;
    EditorEngine_InsertTextAtCursor(txt);
    UpdateTitle();
}

static void DoEditSelectAll() {
    using namespace RawrXD::IDE;
    EditorEngine_SelectAll();
}

static std::string g_findString;
static std::string g_replaceString;
static bool        g_findMatchCase = false;

// RAWRXD_IDE_FIND_REPLACE_DIALOG_001
// DoEditFind used to hardcode g_findString = "TODO" and DoEditReplace used an
// empty replace string, so Ctrl+H silently deleted the first literal "TODO" in
// the open buffer. Both now prompt for real input through a modal dialog built
// in memory (no resource dependency), and refuse to touch the document unless
// the user supplied a non-empty search string.

namespace {
struct FindPromptResult {
    bool        accepted  = false;
    bool        replaceAll = false;
    std::string find;
    std::string replace;
    bool        matchCase = false;
};

constexpr int IDC_FR_FIND    = 1001;
constexpr int IDC_FR_REPLACE = 1002;
constexpr int IDC_FR_CASE    = 1003;
constexpr int IDC_FR_NEXT    = 1004;
constexpr int IDC_FR_REPL    = 1005;
constexpr int IDC_FR_ALL     = 1006;

static std::wstring WidenUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}
static std::string NarrowUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

static std::string GetCtlText(HWND hDlg, int id) {
    HWND h = GetDlgItem(hDlg, id);
    if (!h) return {};
    int len = GetWindowTextLengthW(h);
    if (len <= 0) return {};
    std::wstring w(len + 1, 0);
    GetWindowTextW(h, w.data(), len + 1);
    w.resize(len);
    return NarrowUtf8(w);
}

static void SetCtlText(HWND hDlg, int id, const std::string& utf8) {
    HWND h = GetDlgItem(hDlg, id);
    if (h) SetWindowTextW(h, WidenUtf8(utf8).c_str());
}

static INT_PTR CALLBACK FindDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    FindPromptResult* res = (FindPromptResult*)lp;
    switch (msg) {
    case WM_INITDIALOG: {
        SetCtlText(hDlg, IDC_FR_FIND,    g_findString);
        SetCtlText(hDlg, IDC_FR_REPLACE, g_replaceString);
        CheckDlgButton(hDlg, IDC_FR_CASE, g_findMatchCase ? BST_CHECKED : BST_UNCHECKED);
        SetFocus(GetDlgItem(hDlg, IDC_FR_FIND));
        return TRUE;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wp), code = HIWORD(wp);
        if (code != BN_CLICKED) break;
        if (id == IDC_FR_NEXT || id == IDC_FR_REPL || id == IDC_FR_ALL ||
            id == IDCANCEL || id == IDOK) {
            // Never act on a blank search string: that is how the old stub came
            // to delete text.
            if (id == IDCANCEL) return FALSE;
            std::string find = GetCtlText(hDlg, IDC_FR_FIND);
            if (find.empty()) {
                MessageBoxW(hDlg, L"Enter the text to find.", L"Find",
                            MB_OK | MB_ICONWARNING);
                SetFocus(GetDlgItem(hDlg, IDC_FR_FIND));
                return TRUE;
            }
            res->find       = find;
            res->replace    = GetCtlText(hDlg, IDC_FR_REPLACE);
            res->matchCase  = (GetDlgItem(hDlg, IDC_FR_CASE) != nullptr) &&
                              (SendDlgItemMessage(hDlg, IDC_FR_CASE, BM_GETCHECK, 0, 0) == BST_CHECKED);
            res->accepted   = true;
            res->replaceAll = (id == IDC_FR_ALL);
            EndDialog(hDlg, IDOK);
            return TRUE;
        }
        break;
    }
    case WM_CLOSE:
        return FALSE;
    }
    return FALSE;
}

// Shows the find/replace prompt. `withReplace` adds the replacement field.
//
// The DLGTEMPLATEEX is emitted byte-by-byte rather than by casting a struct,
// because each DLGITEMTEMPLATEEX must start on a DWORD boundary while
// DLGTEMPLATEEX is only 18 bytes. Struct packing cannot express both rules at
// once, so the padding is written explicitly here.
static bool PromptFindReplace(bool withReplace, FindPromptResult* out)
{
    *out = FindPromptResult{};

    // Style bits: WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_CENTER
    const DWORD dlgStyle  = 0x90800000u | 0x00080000u | 0x00040000u | 0x00C00000u;
    // DS_SETFONT = 0x40, WS_EX_CONTROLPARENT = 0x00010000
    const DWORD dlgEx     = 0x00000040u | 0x00010000u;
    // Child styles: WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL
    const DWORD editStyle = 0x50010080u;
    // BUTTON: WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON
    const DWORD btnStyle  = 0x50010000u;
    // AUTOCHECKBOX: BS_AUTOCHECKBOX = 0x03
    const DWORD chkStyle  = 0x50010003u;
    // STATIC: WS_CHILD|WS_VISIBLE|SS_LEFT
    const DWORD statStyle = 0x50000000u;

    std::vector<BYTE> buf;
    auto putDword = [&](DWORD v) { const BYTE* p = (const BYTE*)&v; buf.insert(buf.end(), p, p + 4); };
    auto putWord  = [&](WORD  v) { const BYTE* p = (const BYTE*)&v; buf.insert(buf.end(), p, p + 2); };
    auto putShort = [&](short v) { putWord((WORD)v); };
    auto padTo4   = [&]() { while (buf.size() % 4) buf.push_back(0); };
    auto putStr   = [&](const wchar_t* s) {
        size_t n = wcslen(s) + 1;
        const BYTE* p = (const BYTE*)s;
        buf.insert(buf.end(), p, p + n * sizeof(wchar_t));
    };

    // ---- DLGTEMPLATEEX header ----
    putDword(dlgStyle);
    putDword(dlgEx);
    putWord(0);                       // cdit patched below once items are known
    const size_t cditOffset = buf.size();
    putShort(0); putShort(0);        // x, y
    putShort(withReplace ? 300 : 300);
    putShort(withReplace ? 150 : 100);
    // No menu, default control class, then the caption.
    putWord(0x0000);                  // menu: none
    putWord(0xFFFF);                  // class: default
    putStr(L"RawrXD Find and Replace");
    putWord(9);                       // DS_SETFONT point size
    putStr(L"MS Shell Dlg");          // typeface

    struct Item { short x, y, cx, cy, id; DWORD style; const wchar_t* text; };
    std::vector<Item> items;
    auto add = [&](short x, short y, short cx, short cy, short id, DWORD st, const wchar_t* t) {
        items.push_back(Item{x, y, cx, cy, id, st, t});
    };
    if (withReplace) {
        add(10, 10, 60,  8, -1, statStyle, L"F&ind what:");
        add(78,  8, 190, 14, IDC_FR_FIND, editStyle, L"");
        add(10, 30, 60,  8, -1, statStyle, L"Re&place with:");
        add(78, 28, 190, 14, IDC_FR_REPLACE, editStyle, L"");
        add(78, 48, 190, 10, IDC_FR_CASE, chkStyle, L"Match &case");
        add(190, 74, 70, 16, IDC_FR_NEXT, btnStyle, L"F&ind Next");
        add(190, 94, 70, 16, IDC_FR_REPL, btnStyle, L"&Replace");
        add(190, 114, 70, 16, IDC_FR_ALL,  btnStyle, L"Replace &All");
        add(190,  8, 70, 16, IDCANCEL,    btnStyle, L"Cancel");
    } else {
        add(10, 10, 60,  8, -1, statStyle, L"F&ind what:");
        add(78,  8, 190, 14, IDC_FR_FIND, editStyle, L"");
        add(78, 28, 190, 10, IDC_FR_CASE, chkStyle, L"Match &case");
        add(190, 50, 70, 16, IDC_FR_NEXT, btnStyle, L"F&ind Next");
        add(190,  8, 70, 16, IDCANCEL,    btnStyle, L"Cancel");
    }

    for (const auto& it : items) {
        padTo4();                     // DLGITEMTEMPLATEEX is DWORD-aligned
        putDword(0);                  // helpID
        putDword(0);                  // exStyle
        putDword(it.style);
        putShort(it.x); putShort(it.y); putShort(it.cx); putShort(it.cy);
        putShort(it.id);
        putShort(0);                  // pad the WORD id up to a DWORD boundary
        putDword(0);                  // dwParam (32-bit; dialog is 32-bit safe)
        putShort(0xFFFF);             // window class: default
        putStr(it.text);
        if (it.id == -1) putWord(0xFFFF);   // static controls carry no extra data
    }

    // Patch cdit now that the item count is known.
    *(WORD*)(buf.data() + cditOffset) = (WORD)items.size();

    INT_PTR r = DialogBoxIndirectParamW(GetModuleHandleW(nullptr),
                                        (LPCDLGTEMPLATEW)buf.data(),
                                        g_hwndMain, FindDlgProc, (LPARAM)out);
    return r != 0 && out->accepted;
}

static void ReportFindResult(bool found) {
    using namespace RawrXD::IDE;
    if (!g_hwndMain) return;
    std::wstring base = L"RawrXD Win32IDE";
    std::string path = EditorEngine_FilePath();
    if (!path.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        std::wstring w(n - 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, w.data(), n);
        base += L" - " + w;
    }
    base += found ? L" \u2014 not found" : L" \u2014 found";
    if (EditorEngine_IsModified()) base += L" *";
    SetWindowTextW(g_hwndMain, base.c_str());
}

static void DoEditFind() {
    using namespace RawrXD::IDE;
    FindPromptResult p;
    if (!PromptFindReplace(false, &p)) return;
    g_findString   = p.find;
    g_replaceString= p.replace;
    g_findMatchCase= p.matchCase;
    bool found = EditorEngine_Find(g_findString, g_findMatchCase);
    ReportFindResult(!found);
    if (found) UpdateTitle();
}

static void DoEditFindNext() {
    using namespace RawrXD::IDE;
    if (g_findString.empty()) { DoEditFind(); return; }
    bool found = EditorEngine_Find(g_findString, g_findMatchCase);
    ReportFindResult(!found);
}

static void DoEditReplace() {
    using namespace RawrXD::IDE;
    FindPromptResult p;
    if (!PromptFindReplace(true, &p)) return;
    g_findString   = p.find;
    g_replaceString= p.replace;
    g_findMatchCase= p.matchCase;
    SnapshotForUndo();
    int n = p.replaceAll ? EditorEngine_ReplaceAll(g_findString, g_replaceString, g_findMatchCase)
                         : (EditorEngine_Replace(g_findString, g_replaceString, g_findMatchCase) ? 1 : 0);
    UpdateTitle();
    if (n == 0) {
        ReportFindResult(true);
    } else {
        std::wstring msg = p.replaceAll
            ? L"Replaced " + std::to_wstring(n) + L" occurrence(s)."
            : L"Replaced 1 occurrence.";
        MessageBoxW(g_hwndMain, msg.c_str(), L"Replace", MB_OK | MB_ICONINFORMATION);
    }
}

static void DoEditReplaceAll() {
    using namespace RawrXD::IDE;
    FindPromptResult p;
    if (!PromptFindReplace(true, &p)) return;
    g_findString   = p.find;
    g_replaceString= p.replace;
    g_findMatchCase= p.matchCase;
    SnapshotForUndo();
    int n = EditorEngine_ReplaceAll(g_findString, g_replaceString, g_findMatchCase);
    UpdateTitle();
    if (n == 0) ReportFindResult(true);
    else MessageBoxW(g_hwndMain,
                     (L"Replaced " + std::to_wstring(n) + L" occurrence(s).").c_str(),
                     L"Replace All", MB_OK | MB_ICONINFORMATION);
}

void handleFileCommand(int cmd) {
    switch (cmd) {
    case IDM_FILE_NEW:    DoFileNew();    break;
    case IDM_FILE_OPEN:   DoFileOpen();   break;
    case IDM_FILE_SAVE:   DoFileSave();   break;
    case IDM_FILE_SAVEAS: DoFileSaveAs(); break;
    case IDM_FILE_SAVEALL:DoFileSaveAll();break;
    case IDM_FILE_CLOSE:  DoFileClose();  break;
    case IDM_FILE_EXIT:   DoFileExit();   break;
    // RAWRXD_IDE_SETTINGS_WIRING_001
    case IDM_FILE_SETTINGS: RawrXD::IDE::SettingsGUI_Show(g_hwndMain); break;
    }
}

void handleEditCommand(int cmd) {
    switch (cmd) {
    case IDM_EDIT_UNDO:       DoEditUndo();       break;
    case IDM_EDIT_REDO:       DoEditRedo();       break;
    case IDM_EDIT_CUT:        DoEditCut();        break;
    case IDM_EDIT_COPY:       DoEditCopy();       break;
    case IDM_EDIT_PASTE:      DoEditPaste();      break;
    case IDM_EDIT_SELECT_ALL: DoEditSelectAll();  break;
    case IDM_EDIT_FIND:       DoEditFind();       break;
    case IDM_EDIT_FINDNEXT:   DoEditFindNext();   break;
    case IDM_EDIT_REPLACE:    DoEditReplace();    break;
    case IDM_EDIT_REPLACEALL: DoEditReplaceAll(); break;
    }
}

} // namespace

} // namespace (find/replace prompt helpers)

extern "C" void Win32IDE_Commands_SetMainWindow(HWND hwnd) { g_hwndMain = hwnd; }
extern "C" void Win32IDE_Commands_SetEditorWindow(HWND hwnd) { (void)hwnd; }
extern "C" bool Win32IDE_Commands_Route(int commandId) {
    auto it = g_commandHandlers.find(commandId);
    if (it != g_commandHandlers.end()) { it->second(); return true; }
    if (commandId >= 1000 && commandId < 2000) { handleFileCommand(commandId); return true; }
    if (commandId >= 2100 && commandId < 2200) { handleEditCommand(commandId); return true; }
    return false;
}
extern "C" void Win32IDE_Commands_Register(int id, void (*fn)()) { g_commandHandlers[id] = [fn]() { fn(); }; }
extern "C" void Win32IDE_Commands_SetDirty(bool dirty) { g_dirty = dirty; UpdateTitle(); }

// RAWRXD_IDE_UNDO_COVERAGE_001
// The router owns the undo stack, so it is the natural place to subscribe to
// editor mutations. Called once from WM_CREATE after the editor exists.
extern "C" void Win32IDE_Commands_AttachUndo() {
    RawrXD::IDE::EditorEngine_RegisterMutationHook(&OnEditorMutation);
    PushInitialSnapshot();
}
extern "C" const wchar_t* Win32IDE_Commands_GetCurrentFile() {
    using namespace RawrXD::IDE;
    static std::wstring wpath;
    std::string p = EditorEngine_FilePath();
    if (p.empty()) return nullptr;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, nullptr, 0);
    wpath.resize(wlen - 1);
    MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, wpath.data(), wlen);
    return wpath.c_str();
}
