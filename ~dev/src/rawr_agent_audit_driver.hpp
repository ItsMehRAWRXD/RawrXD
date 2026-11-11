// ============================================================================
// rawr_agent_audit_driver.hpp — RAWR_IDE_AUDIT_E2E_001
// Runtime-owned durable batch audit driver. The OUTER loop is native: the
// runtime (never the model) decides when another batch exists, when the scan
// must (re)run, and when the audit is complete. Each batch is one compact
// model session over <=16 pending candidates with an adjudication-only tool
// surface. Crash/restart resilient: the ledger under .rawr/ owns all state.
// ============================================================================
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>

#include "rawr_audit_state.hpp"

namespace rawrxd {
namespace runstream {
class RawrDeep2Runner;
}

namespace agent {

struct AuditBatchResult {
    uint32_t batchIndex      = 0;
    uint32_t candidatesIn   = 0;   // pending at batch start
    uint32_t candidatesDone  = 0;   // reviewed during this batch
    uint64_t candidatesRemaining = 0;
    uint32_t invalidToolAttempts  = 0;
    uint32_t recoveredToolErrors  = 0;
    uint32_t unrecoveredFailures  = 0;
    int      exitCode         = 1;
};

struct AuditE2EResult {
    int         exitCode            = 1;
    uint64_t    batches             = 0;
    uint64_t    totalModelTurns     = 0;
    uint64_t    totalGeneratedTokens = 0;
    uint32_t    invalidToolAttempts = 0;
    uint32_t    recoveredToolErrors = 0;
    uint32_t    unrecoveredFailures = 0;
    bool        coverageComplete    = false;
    bool        reportEmitted       = false;
    std::string finalReport;
    std::string status              = "FAIL";
};

struct AuditDriverOptions {
    uint32_t batchSize        = 16;
    uint32_t maxStepsPerBatch = 80;   // 16 candidates x ~4 turns + slack
    uint32_t maxTokensPerStep = 192;
    uint64_t maxBatches       = 0;   // 0 = unlimited (until pending==0)
};

// Drives the audit to completion (or driver-option limits). Emits per-batch
// receipts + the global RAWR_IDE_AUDIT_E2E_001 receipt to stderr.
AuditE2EResult runAuditToCompletion(runstream::RawrDeep2Runner& runner,
                                    const std::filesystem::path& workspaceRoot,
                                    const AuditDriverOptions& options);

} // namespace agent
} // namespace rawrxd