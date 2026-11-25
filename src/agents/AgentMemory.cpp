// =============================================================================
// AgentMemory.cpp — CEO agent persistent memory (JSONL/JSON on disk).
// =============================================================================
#include "AgentMemory.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Agents {

namespace {

std::string ReadAll(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void WriteAll(const std::string& path, const std::string& body) {
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (out) out << body;
}

std::string Escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    return out;
}

}  // namespace

AgentMemory::AgentMemory() = default;
AgentMemory::~AgentMemory() = default;

std::string AgentMemory::GetStatePath() const {
    return ".rawrxd/agent/state.json";
}
std::string AgentMemory::GetHistoryPath() const {
    return ".rawrxd/agent/history.jsonl";
}
std::string AgentMemory::GetDecisionPath() const {
    return ".rawrxd/agent/decisions.jsonl";
}
std::string AgentMemory::GetArchitecturePath() const {
    return ".rawrxd/agent/architecture.json";
}

void AgentMemory::EnsureDirectory() const {
    std::filesystem::create_directories(".rawrxd/agent");
}

RawrXD::Agentic::ProjectState AgentMemory::LoadState() const {
    RawrXD::Agentic::ProjectState st;
    const std::string body = ReadAll(GetStatePath());
    if (body.empty()) return st;
    // Minimal reader: "completedComponents":["a","b"]
    const size_t p = body.find("\"completedComponents\"");
    if (p == std::string::npos) return st;
    const size_t open = body.find('[', p);
    const size_t close = body.find(']', open);
    if (open == std::string::npos || close == std::string::npos) return st;
    std::string list = body.substr(open + 1, close - open - 1);
    std::stringstream ss(list);
    std::string item;
    while (std::getline(ss, item, ',')) {
        const size_t q1 = item.find('"');
        const size_t q2 = item.rfind('"');
        if (q1 != std::string::npos && q2 != q1)
            st.completedComponents.push_back(item.substr(q1 + 1, q2 - q1 - 1));
    }
    return st;
}

void AgentMemory::SaveState(const RawrXD::Agentic::ProjectState& state) {
    std::string body = "{\"completedComponents\":[";
    for (size_t i = 0; i < state.completedComponents.size(); ++i) {
        if (i) body += ",";
        body += "\"" + Escape(state.completedComponents[i]) + "\"";
    }
    body += "]}";
    WriteAll(GetStatePath(), body);
}

void AgentMemory::LogTaskCompletion(const std::string& taskId, bool success,
                                    const std::string& details) {
    EnsureDirectory();
    std::ofstream out(GetHistoryPath(), std::ios::app);
    if (!out) return;
    out << "{\"taskId\":\"" << Escape(taskId) << "\",\"success\":"
        << (success ? "true" : "false") << ",\"details\":\"" << Escape(details)
        << "\"}\n";
}

std::vector<nlohmann::json> AgentMemory::GetTaskHistory() const {
    std::vector<nlohmann::json> out;
    const std::string body = ReadAll(GetHistoryPath());
    std::stringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        try {
            out.push_back(nlohmann::json::parse(line));
        } catch (...) {
        }
    }
    return out;
}

void AgentMemory::LogDecision(const std::string& decision,
                              const std::string& reason,
                              const std::string& context) {
    EnsureDirectory();
    std::ofstream out(GetDecisionPath(), std::ios::app);
    if (!out) return;
    out << "{\"decision\":\"" << Escape(decision) << "\",\"reason\":\""
        << Escape(reason) << "\",\"context\":\"" << Escape(context) << "\"}\n";
}

std::vector<nlohmann::json> AgentMemory::GetDecisionLog() const {
    std::vector<nlohmann::json> out;
    const std::string body = ReadAll(GetDecisionPath());
    std::stringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        try {
            out.push_back(nlohmann::json::parse(line));
        } catch (...) {
        }
    }
    return out;
}

void AgentMemory::UpdateArchitecture(const std::string& component,
                                     const nlohmann::json& metadata) {
    EnsureDirectory();
    nlohmann::json arch;
    const std::string body = ReadAll(GetArchitecturePath());
    if (!body.empty()) {
        try {
            arch = nlohmann::json::parse(body);
        } catch (...) {
            arch = nlohmann::json::object();
        }
    }
    arch[component] = metadata;
    WriteAll(GetArchitecturePath(), arch.dump(2));
}

nlohmann::json AgentMemory::GetArchitecture() const {
    const std::string body = ReadAll(GetArchitecturePath());
    if (body.empty()) return nlohmann::json::object();
    try {
        return nlohmann::json::parse(body);
    } catch (...) {
        return nlohmann::json::object();
    }
}

void AgentMemory::Clear() {
    std::filesystem::remove(GetStatePath());
    std::filesystem::remove(GetHistoryPath());
    std::filesystem::remove(GetDecisionPath());
    std::filesystem::remove(GetArchitecturePath());
}

}  // namespace Agents
}  // namespace RawrXD