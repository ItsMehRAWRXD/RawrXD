#pragma once
#include "native_agent_bridge.hpp"
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace RawrXD::NativeBridge {
struct AuditEvent { unsigned long long sequence; std::string action, subject, detail; };
class AuditLog {
public:
    void record(std::string action, std::string subject, std::string detail);
    std::vector<AuditEvent> snapshot() const;
private:
    mutable std::mutex mutex_;
    std::vector<AuditEvent> events_;
    unsigned long long next_ = 1;
};
class ToolPolicy {
public:
    bool allow(std::string name);
    bool deny(std::string name);
    bool permitted(const std::string& name) const;
private:
    mutable std::mutex mutex_;
    std::set<std::string> allowed_, denied_;
};
class ControlledTools {
public:
    ControlledTools(const ToolRegistry& tools, const ToolPolicy& policy, AuditLog& audit);
    Result invoke(const std::string& name, const std::vector<std::string>& args, const std::atomic<bool>& cancel) const;
private:
    const ToolRegistry& tools_;
    const ToolPolicy& policy_;
    AuditLog& audit_;
};
struct Budget {
    size_t maxTasks = 100, maxOutputBytes = 1024*1024;
    bool permits(size_t tasks, size_t outputBytes) const;
};
class Retry {
public:
    static Result execute(const std::function<Result()>& operation, unsigned attempts,
                          const std::atomic<bool>& cancel);
};
class Journal {
public:
    explicit Journal(std::filesystem::path path);
    bool append(const std::string& record, std::string& error);
    std::vector<std::string> read(std::string& error) const;
private:
    std::filesystem::path path_;
    mutable std::mutex mutex_;
};
class EvidenceLedger {
public:
    void add(std::string taskId, Result result);
    std::vector<TaskResult> snapshot() const;
private:
    mutable std::mutex mutex_;
    std::vector<TaskResult> entries_;
};
class DependencyGraph {
public:
    static Result validate(const std::vector<Task>& tasks);
    static std::vector<std::string> order(const std::vector<Task>& tasks, std::string& error);
};
class WorkQueue {
public:
    bool push(Task task);
    std::optional<Task> pop();
    size_t size() const;
private:
    mutable std::mutex mutex_;
    std::deque<Task> tasks_;
    std::set<std::string> ids_;
};
class NativeSession {
public:
    explicit NativeSession(Budget budget);
    Result run(const Task& task, const ControlledTools& tools, const std::atomic<bool>& cancel);
    const EvidenceLedger& evidence() const { return evidence_; }
private:
    Budget budget_;
    EvidenceLedger evidence_;
    size_t tasks_ = 0;
    std::mutex mutex_;
};
Result writeFileAtomic(const std::filesystem::path& root, const std::string& relative, const std::string& contents);
Result compareFile(const std::filesystem::path& root, const std::string& relative, const std::string& expected);
Result searchText(const std::filesystem::path& root, const std::string& relative, const std::string& needle);
Result formatFIM(const std::string& prefix, const std::string& suffix, const std::string& mode);
Result invokeInference(const Inference& inference, const std::string& prompt, const std::atomic<bool>& cancel);
}
