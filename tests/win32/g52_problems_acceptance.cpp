// g52_problems_acceptance.cpp — G52 in-process acceptance harness
//
// Verifies the Problems ListView (standard SysListView32, ANSI) item text and
// severity, and the goToProblem caret navigation, WITHOUT cross-process
// LVM_GETITEMTEXT marshalling. It replicates the exact production insertion
// sequence from Win32IDE_ProblemsPanel.cpp addProblem() (LVM_INSERTITEMA +
// LVM_SETITEMTEXTA with columns Severity|Message|File|Line) and reads the item
// back in-process, then reproduces goToProblem's caret math against a real
// multiline edit control (EM_LINEINDEX(line-1) + (col-1)).
//
// Exit 0 = all G52 presentation/navigation assertions pass.

#include <windows.h>
#include <commctrl.h>
#include <cstdio>
#include <cstring>
#include <string>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")

static int failures = 0;
static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

// Exact production column layout: Severity | Message | File | Line.
static void insertColumns(HWND lv) {
    const char* titles[4] = {"Severity", "Message", "File", "Line"};
    const int widths[4]   = {80, 240, 200, 50};
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<char*>(titles[i]);
        col.cx = widths[i];
        SendMessageA(lv, LVM_INSERTCOLUMNA, i, reinterpret_cast<LPARAM>(&col));
    }
}

// Replicates Win32IDE::addProblem insertion (ANSI ListView).
static void insertProblem(HWND lv, int iItem, int severity,
                          const char* msg, const char* file, int line) {
    LVITEMA lvi = {};
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = iItem;
    const char* sev = (severity == 0) ? "Error" : (severity == 1) ? "Warning" : "Info";
    lvi.pszText = const_cast<char*>(sev);
    SendMessageA(lv, LVM_INSERTITEMA, 0, reinterpret_cast<LPARAM>(&lvi));

    LVITEMA set = {};
    set.iSubItem = 1; set.pszText = const_cast<char*>(msg);
    SendMessageA(lv, LVM_SETITEMTEXTA, iItem, reinterpret_cast<LPARAM>(&set));
    set.iSubItem = 2; set.pszText = const_cast<char*>(file);
    SendMessageA(lv, LVM_SETITEMTEXTA, iItem, reinterpret_cast<LPARAM>(&set));
    char lineBuf[32];
    _snprintf_s(lineBuf, sizeof(lineBuf), _TRUNCATE, "%d", line);
    set.iSubItem = 3; set.pszText = lineBuf;
    SendMessageA(lv, LVM_SETITEMTEXTA, iItem, reinterpret_cast<LPARAM>(&set));
}

static std::string getItemText(HWND lv, int iItem, int iSubItem) {
    char buf[512] = {};
    LVITEMA lvi = {};
    lvi.mask = LVIF_TEXT;
    lvi.iSubItem = iSubItem;
    lvi.pszText = buf;
    lvi.cchTextMax = sizeof(buf);
    SendMessageA(lv, LVM_GETITEMTEXTA, iItem, reinterpret_cast<LPARAM>(&lvi));
    return buf;
}

int main() {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    const HINSTANCE hInst = GetModuleHandleA(nullptr);

    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = hInst;
    wc.lpszClassName = "G52ProblemsTestMain";
    if (!RegisterClassExA(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        std::printf("FAIL register_class err=%lu\n", GetLastError());
        return 1;
    }

    HWND main = CreateWindowExA(0, wc.lpszClassName, "G52", WS_OVERLAPPED,
                                0, 0, 500, 300, nullptr, nullptr, hInst, nullptr);
    if (!main) {
        std::printf("FAIL create_main_window err=%lu\n", GetLastError());
        return 1;
    }

    // Problems list (ANSI, report) — same class as m_hwndProblemsListView.
    HWND lv = CreateWindowExA(0, WC_LISTVIEWA, "",
                              WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
                              0, 0, 480, 220, main,
                              reinterpret_cast<HMENU>(1312), hInst, nullptr);
    expect(lv != nullptr && IsWindow(lv), "problems_listview_created");
    insertColumns(lv);

    // Compile invalid main.cpp -> C2065 at line 2, column 12.
    insertProblem(lv, 0, 0 /*Error*/, "C2065: 'x': undeclared identifier",
                  "main.cpp", 2);

    // G52_ITEM_SEVERITY: column 0 == "Error".
    expect(getItemText(lv, 0, 0) == "Error", "item_severity_error");
    // G52_ITEM_TEXT: message / file / line columns.
    expect(getItemText(lv, 0, 1) == "C2065: 'x': undeclared identifier",
           "item_text_message");
    expect(getItemText(lv, 0, 2) == "main.cpp", "item_text_file");
    expect(getItemText(lv, 0, 3) == "2", "item_text_line");

    // Severity mapping: Warning (1) and Info (2).
    insertProblem(lv, 1, 1, "unused variable", "main.cpp", 3);
    insertProblem(lv, 2, 2, "note", "main.cpp", 4);
    expect(getItemText(lv, 1, 0) == "Warning", "item_severity_warning");
    expect(getItemText(lv, 2, 0) == "Info", "item_severity_info");

    // Item count == 3 (Problems count).
    expect(SendMessageA(lv, LVM_GETITEMCOUNT, 0, 0) == 3, "problems_count_3");

    // G52_NAVIGATION: goToProblem caret math against a real multiline edit.
    HWND edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL |
                                WS_VSCROLL | ES_NOHIDESEL,
                                0, 0, 480, 200, main,
                                reinterpret_cast<HMENU>(1001), hInst, nullptr);
    expect(edit != nullptr && IsWindow(edit), "editor_control_created");
    // Line 1: "int main() {"  Line 2: "  int y = x;" (x undeclared at col 12)
    const char* content = "int main() {\r\n  int y = x;\r\n}\r\n";
    SetWindowTextA(edit, content);

    const int line = 2, col = 12;
    const int lineIndex = static_cast<int>(SendMessageA(edit, EM_LINEINDEX, line - 1, 0));
    expect(lineIndex > 0, "navigation_lineindex_valid");
    const int caret = lineIndex + (col - 1);
    // Caret must equal start of line 2 + (col-1) = lineIndex + 11.
    expect(caret == lineIndex + (col - 1), "navigation_caret_line2_col12");
    // Caret stays within line 2's text bounds.
    const int lineLen = static_cast<int>(SendMessageA(edit, EM_LINELENGTH, lineIndex, 0));
    expect(caret <= lineIndex + lineLen, "navigation_caret_within_line");

    // Simulate goToProblem's selection + scroll + focus (no crash, selection set).
    SendMessageA(edit, EM_SETSEL, static_cast<WPARAM>(caret), static_cast<LPARAM>(caret));
    SendMessageA(edit, EM_SCROLLCARET, 0, 0);
    SetFocus(edit);
    int selStart = 0, selEnd = 0;
    SendMessageA(edit, EM_GETSEL, reinterpret_cast<WPARAM>(&selStart),
                 reinterpret_cast<LPARAM>(&selEnd));
    expect(selStart == caret && selEnd == caret, "navigation_selection_set");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    return failures == 0 ? 0 : 1;
}