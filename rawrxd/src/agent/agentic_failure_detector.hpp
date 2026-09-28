// agentic_failure_detector.hpp — RAWRXD_W3_BATCH_H
//
// Minimal real interface for the failure-detection dependency injected into
// AutonomousWorkflowEngine (src/core/autonomous_workflow_engine.cpp). The
// implementation TU (agentic_failure_detector.cpp) must define every declared
// symbol; nothing here returns synthetic success — a detector that has not
// been fed evidence reports "no failure recorded" explicitly.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Agent {

// Classification of a detected failure inside the autonomous pipeline.
enum class FailureKind : uint32_t {
    None          = 0,
    CompileError  = 1,
    LinkError     = 2,
    TestFailure   = 3,
    Timeout       = 4,
    MissingFile   = 5,
    Unknown       = 0xFFFFFFFF
};

struct FailureRecord {
    FailureKind  kind         = FailureKind::None;
    std::string  sourceFile;    // TU / file the failure is attributed to
    std::string  detail;       // first error line (real capture, not synthetic)
    uint32_t     count        = 0;
    uint64_t     timestampMs  = 0;
};

// AgenticFailureDetector — accumulates real failure evidence from stage
// outputs (build/test logs) and answers "did the last stage fail?".
class AgenticFailureDetector {
public:
    AgenticFailureDetector() = default;
    ~AgenticFailureDetector() = default;

    // Ingest one stage output buffer (build/test console text). Real scan:
    // counts lines matching compiler/linker/test-failure patterns.
    void ingestStageOutput(const char* stageName,
                           const std::string& consoleText);

    // True when at least one failure record exists and none was cleared.
    bool hasFailure() const;

    // Most recent failure record (kind/first-line); valid when hasFailure().
    const FailureRecord& lastFailure() const;

    // Clear accumulated evidence (start of a retry round).
    void clear();

    size_t failureCount() const { return m_records.size(); }

private:
    std::vector<FailureRecord> m_records;
};

} // namespace Agent
} // namespace RawrXD