#pragma once
// In-chat agent step strip: thought timers + tool chips (powershell/explored).
// ListBox above chat + optional onRow mirror into the transcript for E2E visibility.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <windows.h>

#ifndef IDC_AGENT_STEP_STRIP
#define IDC_AGENT_STEP_STRIP 1225
#endif
#ifndef IDT_AGENT_THOUGHT
#define IDT_AGENT_THOUGHT 0xA571
#endif

struct AgentStepTimeline {
    HWND hwndList = nullptr;
    ULONGLONG thoughtStartMs = 0;
    bool thoughtOpen = false;
    std::string lastLine;
    // Fired for every visible row except the idle [ready] placeholder and live ticks.
    std::function<void(const std::string&)> onRow;

    void create(HWND parent, HINSTANCE inst, HFONT font, int x, int y, int w, int h);
    void clear();
    void beginThought();
    void closeThoughtIfOpen();
    // Update open [thought] row with live elapsed time (list only; no chat spam).
    void refreshThoughtElapsed();
    void addChip(const std::string& kind, const std::string& detail);
    void addTool(const std::string& toolName, const std::string& target, int exitCode, bool ok);
    void addExplored(const std::string& pathOrNote);
    void layout(int x, int y, int w, int h);
    std::vector<std::string> snapshotRows() const;
    void restoreRows(const std::vector<std::string>& rows);

private:
    void appendRow(const char* text, bool mirror);
    void replaceLastRow(const char* text);
};
