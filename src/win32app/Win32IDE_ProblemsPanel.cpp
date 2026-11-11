// Win32IDE_ProblemsPanel.cpp — sole owner of addProblem/clearProblems (Batch17).
// Product path: m_problems + IDC_PANEL_PROBLEMS_LIST (1312) for goToProblem/1399.
#include "Win32IDE.h"
#include <commctrl.h>
#include <windowsx.h>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")

#define TIMER_PROBLEMS_AUTO_REFRESH  9050
#define PROBLEMS_REFRESH_INTERVAL_MS 2000
#ifndef IDC_PANEL_PROBLEMS_LIST
#define IDC_PANEL_PROBLEMS_LIST 1312
#endif

namespace {
struct ProblemStringHeap { char* file; char* msg; };
static std::vector<ProblemStringHeap*> g_problemHeapObjects;
static std::vector<char*> g_problemStringHeap;

static void freeProblemHeaps() {
    for (auto* h : g_problemHeapObjects) {
        delete[] h->file;
        delete[] h->msg;
        delete h;
    }
    g_problemHeapObjects.clear();
    for (auto* p : g_problemStringHeap) delete[] p;
    g_problemStringHeap.clear();
}
} // namespace

void Win32IDE::createProblemsPanel() {
    if (m_hwndProblemsPanel) return;
    m_hwndProblemsPanel = CreateWindowExW(0, WC_LISTVIEWW, L"Problems",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL,
        0, 0, 400, 200, m_hwndMain, nullptr, m_hInstance, nullptr);
    if (!m_hwndProblemsPanel) return;
    ListView_SetExtendedListViewStyle(m_hwndProblemsPanel,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.pszText = (LPWSTR)L"Severity"; col.cx = 80;
    SendMessageW(m_hwndProblemsPanel, LVM_INSERTCOLUMNW, 0, (LPARAM)&col);
    col.pszText = (LPWSTR)L"Message"; col.cx = 240;
    SendMessageW(m_hwndProblemsPanel, LVM_INSERTCOLUMNW, 1, (LPARAM)&col);
    col.pszText = (LPWSTR)L"File"; col.cx = 200;
    SendMessageW(m_hwndProblemsPanel, LVM_INSERTCOLUMNW, 2, (LPARAM)&col);
    col.pszText = (LPWSTR)L"Line"; col.cx = 50;
    SendMessageW(m_hwndProblemsPanel, LVM_INSERTCOLUMNW, 3, (LPARAM)&col);
    SetTimer(m_hwndProblemsPanel, TIMER_PROBLEMS_AUTO_REFRESH,
             PROBLEMS_REFRESH_INTERVAL_MS, nullptr);
    ShowWindow(m_hwndProblemsPanel, SW_HIDE);
}

void Win32IDE::addProblem(const std::string& file, int line, int col,
                          const std::string& msg, int severity) {
    ProblemItem problem;
    problem.file = file;
    problem.line = line;
    problem.column = col > 0 ? col : 1;
    problem.message = msg;
    problem.severity = severity;
    m_problems.push_back(problem);
    if (severity == 0) m_errorCount++;
    else if (severity == 1) m_warningCount++;

    if (!m_hwndProblemsListView || !IsWindow(m_hwndProblemsListView)) {
        updatePanelContent();
        updateEnhancedStatusBar();
        return;
    }

    LVITEMA lvi = {};
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = static_cast<int>(m_problems.size() - 1);
    const char* severityStr =
        (severity == 0) ? "Error" : (severity == 1) ? "Warning" : "Info";
    lvi.pszText = const_cast<char*>(severityStr);
    auto* heap = new ProblemStringHeap{};
    heap->file = new char[file.length() + 1];
    strcpy_s(heap->file, file.length() + 1, file.c_str());
    heap->msg = new char[msg.length() + 1];
    strcpy_s(heap->msg, msg.length() + 1, msg.c_str());
    g_problemHeapObjects.push_back(heap);
    lvi.lParam = reinterpret_cast<LPARAM>(heap);
    ListView_InsertItem(m_hwndProblemsListView, &lvi);

    LVITEMA set = {};
    set.iSubItem = 1; set.pszText = heap->msg;
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&set);
    set.iSubItem = 2; set.pszText = heap->file;
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&set);
    char lineBuf[32];
    _snprintf_s(lineBuf, sizeof(lineBuf), _TRUNCATE, "%d", line);
    char* lineHeap = new char[strlen(lineBuf) + 1];
    strcpy_s(lineHeap, strlen(lineBuf) + 1, lineBuf);
    g_problemStringHeap.push_back(lineHeap);
    set.iSubItem = 3; set.pszText = lineHeap;
    SendMessage(m_hwndProblemsListView, LVM_SETITEMTEXTA, lvi.iItem, (LPARAM)&set);

    switchPanelTab(PanelTab::Problems);
    updatePanelContent();
    updateEnhancedStatusBar();
}

void Win32IDE::addProblem(const std::string& file, int line,
                          const std::string& message, OutputSeverity severity) {
    int sev = 2;
    if (severity == OutputSeverity::Error) sev = 0;
    else if (severity == OutputSeverity::Warning) sev = 1;
    addProblem(file, line, 1, message, sev);
}

void Win32IDE::clearProblems() {
    freeProblemHeaps();
    m_problems.clear();
    m_errorCount = 0;
    m_warningCount = 0;
    for (auto& pane : m_terminalPanes) pane.diagCarry.clear();
    if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
        ListView_DeleteAllItems(m_hwndProblemsListView);
    if (m_hwndProblemsPanel && IsWindow(m_hwndProblemsPanel))
        ListView_DeleteAllItems(m_hwndProblemsPanel);
    updatePanelContent();
    updateEnhancedStatusBar();
}
