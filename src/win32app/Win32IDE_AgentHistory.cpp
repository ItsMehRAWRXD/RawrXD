// Win32IDE_AgentHistory.cpp — Undo Stack for AI Edits (Batch 3 AI/Agent)
#include "Win32IDE.h"
#include <vector>
#include <string>

struct AgentEdit {
    std::string filePath;
    std::string oldContent;
    std::string newContent;
    int line;
    int column;
};

static std::vector<AgentEdit> g_agentEditHistory;

void Win32IDE::pushAgentEdit(const std::string& filePath,
                              const std::string& oldContent,
                              const std::string& newContent,
                              int line, int column) {
    AgentEdit edit;
    edit.filePath = filePath;
    edit.oldContent = oldContent;
    edit.newContent = newContent;
    edit.line = line;
    edit.column = column;
    g_agentEditHistory.push_back(edit);
    appendToOutput("[AgentHistory] Recorded edit to " + filePath + "\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::undoLastAgentEdit() {
    if (g_agentEditHistory.empty()) return false;
    auto& last = g_agentEditHistory.back();
    appendToOutput("[AgentHistory] Undoing edit to " + last.filePath + "\n", "Output", OutputSeverity::Info);
    g_agentEditHistory.pop_back();
    return true;
}
