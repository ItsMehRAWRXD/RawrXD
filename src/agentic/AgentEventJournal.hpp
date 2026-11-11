#pragma once
// Append-only agent event journal — shared contract for IDE/CLI/workers.
// Reuses rawr::live::Sink JSONL schema. Evidence, not authority. PROMOTE=0.
#include "RawrSwarmEvents.hpp"
#include <filesystem>
#include <string>

namespace RawrXD {
namespace Agent {

class AgentEventJournal {
public:
    explicit AgentEventJournal(std::filesystem::path path)
        : path_(std::move(path)), sink_(path_.string()) {}

    const std::filesystem::path& path() const { return path_; }

    bool Emit(rawr::live::Event e, std::string* error = nullptr) {
        return sink_.emit(std::move(e), error);
    }

    bool ToolStart(const std::string& worker, const std::string& tool,
                   const std::string& detail, const std::string& task = {}) {
        rawr::live::Event e;
        e.worker = worker;
        e.kind = "tool";
        e.phase = "start";
        e.title = tool;
        e.detail = detail;
        e.task = task;
        return Emit(std::move(e));
    }

    bool ToolFinish(const std::string& worker, const std::string& tool,
                    int exitCode, const std::string& detail,
                    const std::string& task = {}) {
        rawr::live::Event e;
        e.worker = worker;
        e.kind = "tool";
        e.phase = (exitCode == 0) ? "ok" : "fail";
        e.title = tool;
        e.detail = detail;
        e.task = task;
        e.exitCode = exitCode;
        return Emit(std::move(e));
    }

    bool Checkpoint(const std::string& worker, const std::string& title,
                    const std::string& task = {}) {
        rawr::live::Event e;
        e.worker = worker;
        e.kind = "checkpoint";
        e.phase = "ok";
        e.title = title;
        e.task = task;
        return Emit(std::move(e));
    }

private:
    std::filesystem::path path_;
    rawr::live::Sink sink_;
};

} // namespace Agent
} // namespace RawrXD
