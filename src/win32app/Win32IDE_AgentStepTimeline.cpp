#include "Win32IDE_AgentStepTimeline.h"
#include <cstdio>

void AgentStepTimeline::appendRow(const char* text, bool mirror) {
    if (!hwndList || !IsWindow(hwndList) || !text) return;
    lastLine = text;
    SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)text);
    const LRESULT n = SendMessageA(hwndList, LB_GETCOUNT, 0, 0);
    if (n > 0) SendMessageA(hwndList, LB_SETTOPINDEX, (WPARAM)(n - 1), 0);
    if (mirror && onRow) onRow(lastLine);
}

void AgentStepTimeline::replaceLastRow(const char* text) {
    if (!hwndList || !IsWindow(hwndList) || !text) return;
    const LRESULT n = SendMessageA(hwndList, LB_GETCOUNT, 0, 0);
    if (n <= 0) return;
    SendMessageA(hwndList, LB_DELETESTRING, (WPARAM)(n - 1), 0);
    lastLine = text;
    SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)text);
    SendMessageA(hwndList, LB_SETTOPINDEX, (WPARAM)(n - 1), 0);
}

void AgentStepTimeline::create(HWND parent, HINSTANCE inst, HFONT font, int x, int y, int w, int h) {
    if (!parent || hwndList) return;
    // No LBS_NOTIFY: LB_ADDSTRING/DELETESTRING must not emit LBN_* into the
    // subclassed sidebar → main WM_COMMAND path (nested StatusBar/TabCtrl
    // work under ListBox SendMessage faults comctl32 on Request A).
    hwndList = CreateWindowExA(
        WS_EX_CLIENTEDGE, "LISTBOX", nullptr,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
        x, y, w, h, parent, (HMENU)(INT_PTR)IDC_AGENT_STEP_STRIP, inst, nullptr);
    if (hwndList && font) SendMessage(hwndList, WM_SETFONT, (WPARAM)font, TRUE);
    appendRow("[ready] thought / tool chips / explored / powershell", false);
}

void AgentStepTimeline::clear() {
    if (!hwndList) return;
    SendMessageA(hwndList, LB_RESETCONTENT, 0, 0);
    thoughtOpen = false;
    thoughtStartMs = 0;
    lastLine.clear();
    appendRow("[ready] thought / tool chips / explored / powershell", false);
}

void AgentStepTimeline::beginThought() {
    if (!hwndList) return;
    closeThoughtIfOpen();
    thoughtStartMs = GetTickCount64();
    thoughtOpen = true;
    appendRow("[thought] 0.000s ...", true);
}

void AgentStepTimeline::refreshThoughtElapsed() {
    if (!hwndList || !thoughtOpen || !IsWindow(hwndList)) return;
    try {
        const ULONGLONG dt = GetTickCount64() - thoughtStartMs;
        char buf[96];
        std::snprintf(buf, sizeof(buf), "[thought] %llu.%03llus ...",
                      (unsigned long long)(dt / 1000ull),
                      (unsigned long long)(dt % 1000ull));
        replaceLastRow(buf);
    } catch (...) {
    }
}

void AgentStepTimeline::closeThoughtIfOpen() {
    if (!hwndList || !thoughtOpen) return;
    const ULONGLONG dt = GetTickCount64() - thoughtStartMs;
    char buf[96];
    std::snprintf(buf, sizeof(buf), "[thought] %llu.%03llus",
                  (unsigned long long)(dt / 1000ull),
                  (unsigned long long)(dt % 1000ull));
    replaceLastRow(buf);
    if (onRow) onRow(lastLine);
    thoughtOpen = false;
}

void AgentStepTimeline::addChip(const std::string& kind, const std::string& detail) {
    if (!hwndList) return;
    closeThoughtIfOpen();
    char buf[512];
    std::snprintf(buf, sizeof(buf), "[%s] %.400s", kind.c_str(), detail.c_str());
    // PowerShell/shell chips stay on the step strip only — mirroring them into
    // Copilot chat via onRow produced the observed "[powershell] ?" transcript leak.
    const bool mirrorToChat = !(kind == "powershell" || kind == "shell" || kind == "pwsh");
    appendRow(buf, mirrorToChat);
}

void AgentStepTimeline::addTool(const std::string& toolName, const std::string& target,
                                int exitCode, bool ok) {
    if (!hwndList) return;
    closeThoughtIfOpen();
    std::string kind = "tool";
    std::string lower = toolName;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (lower.find("powershell") != std::string::npos || lower.find("shell") != std::string::npos ||
        lower.find("pwsh") != std::string::npos || lower == "bash" || lower == "cmd") {
        kind = "powershell";
    } else if (lower.find("explor") != std::string::npos || lower.find("read") != std::string::npos ||
               lower.find("glob") != std::string::npos || lower.find("grep") != std::string::npos ||
               lower.find("list") != std::string::npos) {
        kind = "explored";
    }
    char buf[640];
    std::snprintf(buf, sizeof(buf), "[%s:%s] %s exit=%d (%.360s)",
                  kind.c_str(), toolName.c_str(), ok ? "ok" : "fail", exitCode, target.c_str());
    const bool mirrorToChat = (kind != "powershell");
    appendRow(buf, mirrorToChat);
}

void AgentStepTimeline::addExplored(const std::string& pathOrNote) {
    addChip("explored", pathOrNote);
}

void AgentStepTimeline::layout(int x, int y, int w, int h) {
    if (hwndList) MoveWindow(hwndList, x, y, w, h, TRUE);
}

std::vector<std::string> AgentStepTimeline::snapshotRows() const {
    std::vector<std::string> rows;
    if (!hwndList) return rows;
    const LRESULT n = SendMessageA(hwndList, LB_GETCOUNT, 0, 0);
    for (LRESULT i = 0; i < n; ++i) {
        const LRESULT len = SendMessageA(hwndList, LB_GETTEXTLEN, (WPARAM)i, 0);
        if (len <= 0) continue;
        std::string text(static_cast<size_t>(len) + 1, '\0');
        SendMessageA(hwndList, LB_GETTEXT, (WPARAM)i, (LPARAM)text.data());
        text.resize(static_cast<size_t>(len));
        rows.push_back(std::move(text));
    }
    return rows;
}

void AgentStepTimeline::restoreRows(const std::vector<std::string>& rows) {
    if (!hwndList) return;
    SendMessageA(hwndList, LB_RESETCONTENT, 0, 0);
    thoughtOpen = false;
    thoughtStartMs = 0;
    lastLine.clear();
    if (rows.empty()) {
        appendRow("[ready] thought / tool chips / explored / powershell", false);
        return;
    }
    for (const auto& row : rows) {
        appendRow(row.c_str(), false);
    }
}
