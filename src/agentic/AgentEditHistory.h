// =============================================================================
// AgentEditHistory.h — AF05 undo stack with real file-byte restore
// =============================================================================
// Stores before/after snapshots for agent edits. undoLast() restores prior
// file bytes from oldContent (not a no-op stack pop). Header-only so IDE and
// smoke share one SSOT without pulling Win32IDE.
// =============================================================================
#pragma once

#include <fstream>
#include <string>
#include <vector>
#include <filesystem>

namespace RawrXD {
namespace Agent {

struct AgentEditSnapshot {
    std::string filePath;
    std::string oldContent;
    std::string newContent;
    int line = 0;
    int column = 0;
};

inline bool WriteFileBytes(const std::string& path, const std::string& bytes) {
    if (path.empty()) return false;
    std::error_code ec;
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, ec);
    const std::string tmp = path + ".agent_undo_tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!out) return false;
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return static_cast<bool>(out);
    }
    return true;
}

inline bool ReadFileBytes(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

class AgentEditHistory {
public:
    void push(const AgentEditSnapshot& edit) { m_stack.push_back(edit); }

    // Restore prior file bytes from the stored oldContent snapshot, then pop.
    bool undoLast() {
        if (m_stack.empty()) return false;
        const AgentEditSnapshot last = m_stack.back();
        if (!WriteFileBytes(last.filePath, last.oldContent)) return false;
        m_stack.pop_back();
        return true;
    }

    size_t size() const { return m_stack.size(); }
    void clear() { m_stack.clear(); }
    const AgentEditSnapshot* peek() const {
        return m_stack.empty() ? nullptr : &m_stack.back();
    }

private:
    std::vector<AgentEditSnapshot> m_stack;
};

} // namespace Agent
} // namespace RawrXD
