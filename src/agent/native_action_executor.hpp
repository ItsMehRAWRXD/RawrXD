#pragma once

#include "native_process.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

struct NativeAction {
    enum class Type { InvokeCommand, QueryUser };
    Type type = Type::InvokeCommand;
    std::string command;
    std::vector<std::string> args;
    std::string description;
    bool executed = false;
    bool success = false;
    std::string output;
    std::string error;
};

struct NativeExecutionContext {
    std::string projectRoot;
    int commandTimeoutMs = 30000;
    int planTimeoutMs = 300000;
    unsigned maxRetries = 2;
    unsigned maxActions = 256;
};

class NativeActionExecutor final {
public:
    using ActionCallback = std::function<void(size_t, const NativeAction&)>;
    using QueryCallback = std::function<bool(const NativeAction&)>;

    explicit NativeActionExecutor(NativeExecutionContext context = {})
        : context_(std::move(context)) {}
    ~NativeActionExecutor() { cancel(); join(); }

    NativeActionExecutor(const NativeActionExecutor&) = delete;
    NativeActionExecutor& operator=(const NativeActionExecutor&) = delete;

    void setActionCallback(ActionCallback cb) { onAction_ = std::move(cb); }
    void setQueryCallback(QueryCallback cb) { onQuery_ = std::move(cb); }
    bool running() const { return running_.load(); }
    void cancel() { cancelled_.store(true); }
    void join() { if (worker_.joinable()) worker_.join(); }

    bool execute(NativeAction action) {
        if (cancelled_.load()) { action.error = "CANCELLED"; return false; }
        if (action.type == NativeAction::Type::QueryUser) {
            if (!onQuery_) { action.error = "QUERY_PENDING"; return false; }
            action.success = onQuery_(action);
            action.executed = true;
            if (!action.success) action.error = "USER_QUERY_REJECTED";
            return action.success;
        }
        const auto result = NativeProcess::execute(action.command, action.args,
                                                   context_.projectRoot,
                                                   context_.commandTimeoutMs);
        action.executed = true;
        action.success = result.success;
        action.output = result.stdoutOutput + result.stderrOutput;
        action.error = result.error.empty() && !result.success
            ? "NONZERO_EXIT_CODE:" + std::to_string(result.exitCode)
            : result.error;
        return action.success;
    }

    bool executePlan(std::vector<NativeAction> actions, bool stopOnError = true) {
        if (running_.exchange(true)) return false;
        cancelled_.store(false);
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(context_.planTimeoutMs);
        bool overall = true;
        if (actions.size() > context_.maxActions) {
            running_.store(false); return false;
        }
        for (size_t i = 0; i < actions.size(); ++i) {
            if (cancelled_.load() || std::chrono::steady_clock::now() >= deadline) {
                overall = false; break;
            }
            NativeAction& action = actions[i];
            bool ok = false;
            for (unsigned attempt = 0; attempt <= context_.maxRetries; ++attempt) {
                if (attempt != 0) break; // retries require a caller-supplied corrective change
                ok = execute(action);
            }
            if (onAction_) onAction_(i, action);
            if (!ok) { overall = false; if (stopOnError) break; }
        }
        running_.store(false);
        return overall;
    }

    void executePlanAsync(std::vector<NativeAction> actions, bool stopOnError = true) {
        join();
        worker_ = std::thread([this, actions = std::move(actions), stopOnError]() mutable {
            executePlan(std::move(actions), stopOnError);
        });
    }

private:
    NativeExecutionContext context_;
    std::atomic_bool cancelled_{false};
    std::atomic_bool running_{false};
    std::thread worker_;
    ActionCallback onAction_;
    QueryCallback onQuery_;
};
