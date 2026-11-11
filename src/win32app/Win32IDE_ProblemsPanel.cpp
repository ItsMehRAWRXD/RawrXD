// Win32IDE_ProblemsPanel.cpp — Unified Problems Panel (Batch 4 P07)
// Aggregates: LSP, SAST, SCA, Secrets, Build. Auto-refreshes on timer.
#include "Win32IDE.h"
#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <string>
#include <sstream>

#pragma comment(lib, "comctl32.lib")

#define TIMER_PROBLEMS_AUTO_REFRESH  9050
#define PROBLEMS_REFRESH_INTERVAL_MS 2000

static Win32IDE* g_pProblemsIDE = nullptr;
static size_t s_lastProblemsHash = 0;

namespace {

WNDPROC g_origProblemsPanelProc = nullptr;
HWND g_hwndProblemsMain = nullptr;

#ifndef LVM_SETITEMTEXTW
#define LVM_SETITEMTEXTW (LVM_FIRST + 116)
#endif
#ifndef LVM_INSERTITEMW
#define LVM_INSERTITEMW  (LVM_FIRST + 77)
#endif

struct ProblemEntry {
    int severity;
    std::string message;
    std::string path;
    int line;
};

static std::vector<ProblemEntry> g_problems;

static size_t computeProblemsHash(const std::vector<ProblemEntry>& entries) {
    size_t h = entries.size();
    for (const auto& e : entries) {
        h ^= std::hash<int>{}(e.severity) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(e.message) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(e.path) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int>{}(e.line) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
}

} // namespace

void Win32IDE::createProblemsPanel() {
    if (m_hwndProblemsPanel) return;

    m_hwndProblemsPanel = CreateWindowExW(0, WC_LISTVIEWW, L"Problems",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL,
        0, 0, 400, 200, m_hwndMain, nullptr, m_hInstance, nullptr);

    ListView_SetExtendedListViewStyle(m_hwndProblemsPanel,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;

    col.pszText = (LPWSTR)L"Severity";
    col.cx = 80;
    ListView_InsertColumnW(m_hwndProblemsPanel, 0, &col);

    col.pszText = (LPWSTR)L"Message";
    col.cx = 240;
    ListView_InsertColumnW(m_hwndProblemsPanel, 1, &col);

    col.pszText = (LPWSTR)L"File";
    col.cx = 200;
    ListView_InsertColumnW(m_hwndProblemsPanel, 2, &col);

    col.pszText = (LPWSTR)L"Line";
    col.cx = 50;
    ListView_InsertColumnW(m_hwndProblemsPanel, 3, &col);

    SetTimer(m_hwndProblemsPanel, TIMER_PROBLEMS_AUTO_REFRESH,
             PROBLEMS_REFRESH_INTERVAL_MS, nullptr);

    appendToOutput("[ProblemsPanel] Problems panel created.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::addProblem(const std::string& file, int line, const std::string& message, OutputSeverity severity) {
    ProblemEntry entry;
    entry.severity = static_cast<int>(severity);
    entry.message = message;
    entry.path = file;
    entry.line = line;
    g_problems.push_back(entry);
    s_lastProblemsHash = computeProblemsHash(g_problems);
}

void Win32IDE::clearProblems() {
    g_problems.clear();
    if (m_hwndProblemsPanel) {
        ListView_DeleteAllItems(m_hwndProblemsPanel);
    }
    s_lastProblemsHash = 0;
}
