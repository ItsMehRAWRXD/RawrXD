#pragma once
// RawrXD native, dependency-free (C++20). Event data is evidence, not authority.
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace rawr::live {

// Explicit, stable wire schema: one UTF-8 JSON object per line (JSONL).
// "reason" is a model-supplied rationale/status summary, NOT private chain of thought.
struct Event {
    std::string ts;       // ISO UTC timestamp, assigned if missing
    std::string worker;   // worker id or "main"
    std::string kind;     // agent, plan, reason, read, edit, diff, shell, output, test, build, error, checkpoint
    std::string phase;    // start, progress, ok, fail, info (NOT inferred from title)
    std::string title;    // human readable operation
    std::string detail;   // path, command, selected diff hunk, actual stdout/stderr
    std::string task;     // optional task id
    int exitCode = -1;   // -1 means unknown; no implied success
    uint64_t seq = 0;    // monotonically increasing per writer, not global across processes
    bool sensitive = false; // if set, title/detail written as [redacted]
};

std::string escapeJson(std::string_view s);
std::string serialize(const Event& e);
bool parse(std::string_view line, Event& out); // strict for required fields
std::string utcNow();

class Sink {
public:
    explicit Sink(std::string path);
    bool emit(Event e, std::string* error = nullptr); // threadsafe; false on I/O failure
    const std::string& path() const { return path_; }
private:
    std::string path_;
    std::mutex mutex_;
    uint64_t sequence_ = 0;
};

// Production adapter for existing RawrXD agent/tool execution.
// Call these at the REAL tool boundary; do not infer success from model text.
class ToolTrace {
public:
    ToolTrace(Sink& sink, std::string worker, std::string kind,
              std::string title, std::string detail = {}, std::string task = {});
    void output(std::string chunk, bool sensitive = false);
    void reasoningSummary(std::string summary); // only emitted model/provider summary
    void finish(int realExitCode, std::string detail = {});
    ~ToolTrace(); // emits "interrupted" if never completed; NEVER emits fabricated success
private:
    Sink& sink_;
    std::string worker_, kind_, title_, task_;
    bool finished_ = false;
};

// Opens a real second terminal window on Windows, attached to the same JSONL stream.
// Returns false on unsupported platforms or CreateProcessW failure.
bool openViewerWindow(const std::string& viewerExe, const std::string& eventPath,
                      std::string* error = nullptr);

} // namespace rawr::live
