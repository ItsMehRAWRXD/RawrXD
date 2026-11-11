// Win32IDE_AgentHistory.cpp — Undo Stack for AI Edits (Batch 3 AI/Agent)
// Gap 7: undoLastAgentEdit restores prior file bytes from stored snapshots.
#include "Win32IDE.h"
#include "agentic/AgentEditHistory.h"
#include <unordered_map>

static RawrXD::Agent::AgentEditHistory g_agentEditHistory;
// Last-known bytes per path so write/edit tool results can record before/after.
static std::unordered_map<std::string, std::string> g_agentFileSnapshots;

void Win32IDE::pushAgentEdit(const std::string& filePath,
                              const std::string& oldContent,
                              const std::string& newContent,
                              int line, int column) {
    RawrXD::Agent::AgentEditSnapshot edit;
    edit.filePath = filePath;
    edit.oldContent = oldContent;
    edit.newContent = newContent;
    edit.line = line;
    edit.column = column;
    g_agentEditHistory.push(edit);
    g_agentFileSnapshots[filePath] = newContent;
    appendToOutput("[AgentHistory] Recorded edit to " + filePath +
                   " before_bytes=" + std::to_string(oldContent.size()) +
                   " after_bytes=" + std::to_string(newContent.size()) + "\n",
                   "Output", OutputSeverity::Info);
}

bool Win32IDE::undoLastAgentEdit() {
    if (g_agentEditHistory.size() == 0) return false;
    const auto* peek = g_agentEditHistory.peek();
    if (!peek) return false;
    const std::string path = peek->filePath;
    const std::string restored = peek->oldContent;
    if (!g_agentEditHistory.undoLast()) {
        appendToOutput("[AgentHistory] Undo failed writing " + path + "\n",
                       "Errors", OutputSeverity::Error);
        return false;
    }
    g_agentFileSnapshots[path] = restored;
    if (!m_currentFile.empty() && m_currentFile == path) {
        setEditorText(restored);
    }
    appendToOutput("[AgentHistory] Restored " + path +
                   " bytes=" + std::to_string(restored.size()) + "\n",
                   "Output", OutputSeverity::Info);
    return true;
}

// Seed / refresh path snapshot (call on read tools) so next write has a before.
void Win32IDE::snapshotAgentFileBytes(const std::string& filePath) {
    if (filePath.empty()) return;
    std::string bytes;
    if (RawrXD::Agent::ReadFileBytes(filePath, bytes)) {
        g_agentFileSnapshots[filePath] = bytes;
    } else {
        g_agentFileSnapshots[filePath] = std::string();
    }
}

// Record write/edit after tool mutated disk: before = prior snapshot, after = disk.
bool Win32IDE::recordAgentFileMutation(const std::string& filePath) {
    if (filePath.empty()) return false;
    std::string after;
    if (!RawrXD::Agent::ReadFileBytes(filePath, after)) return false;
    std::string before;
    auto it = g_agentFileSnapshots.find(filePath);
    if (it != g_agentFileSnapshots.end()) before = it->second;
    else before.clear(); // create: prior bytes empty
    if (before == after) return false;
    pushAgentEdit(filePath, before, after, 0, 0);
    return true;
}
