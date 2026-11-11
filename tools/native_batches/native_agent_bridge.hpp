#pragma once
#include <atomic>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace RawrXD::NativeBridge {
struct Result { bool ok = false; std::string output; std::string error; };
using Tool = std::function<Result(const std::vector<std::string>&, const std::atomic<bool>&)>;
class ToolRegistry {
public:
    bool registerTool(std::string name, Tool tool);
    Result execute(const std::string& name, const std::vector<std::string>& args, const std::atomic<bool>& cancel) const;
    std::vector<std::string> names() const;
private:
    mutable std::mutex mu_;
    std::map<std::string, Tool> tools_;
};
struct Task { std::string id, tool; std::vector<std::string> args; std::vector<std::string> dependencies; };
struct TaskResult { std::string id; Result result; };
class Planner {
public:
    bool add(Task task);
    std::vector<TaskResult> execute(const ToolRegistry& tools, const std::atomic<bool>& cancel) const;
private:
    std::vector<Task> tasks_;
};
class AgentMemory {
public:
    explicit AgentMemory(std::filesystem::path root);
    bool save(const std::string& key, const std::string& value, std::string& error) const;
    std::optional<std::string> load(const std::string& key, std::string& error) const;
private:
    std::filesystem::path root_;
};
class AgentOrchestrator {
public:
    ToolRegistry& tools() { return tools_; }
    bool submit(Task task) { return planner_.add(std::move(task)); }
    std::vector<TaskResult> run() { cancel_.store(false); return planner_.execute(tools_, cancel_); }
    void cancel() { cancel_.store(true); }
private:
    ToolRegistry tools_;
    Planner planner_;
    std::atomic<bool> cancel_{false};
};
using Inference = std::function<Result(const std::string&, const std::atomic<bool>&)>;
class CEOAgent {
public:
    explicit CEOAgent(Inference inference) : inference_(std::move(inference)) {}
    Result plan(const std::string& goal, const std::atomic<bool>& cancel) const;
private:
    Inference inference_;
};
std::string buildFIM(const std::string& prefix, const std::string& suffix,
                     const std::string& start, const std::string& middle, const std::string& end);
void registerFileTools(ToolRegistry& tools, std::filesystem::path workspace);
}
