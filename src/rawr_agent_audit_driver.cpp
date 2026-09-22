// ============================================================================
// rawr_agent_audit_driver.cpp — RAWR_IDE_AUDIT_E2E_001 implementation.
//
// The runtime owns the outer loop:
//   while (pending > 0) { run one compact model batch over <=16 candidates }
// The model never decides whether more work exists. Tool surface during
// adjudication is restricted (no workspace.list / audit.scan / build / test)
// so tool-selection errors are structurally unlikely and the schema stays
// small. Batch state is durable: .rawr/ ledger survives crash/restart, and
// the scan epoch rejects reviews of candidates from a stale workspace
// generation.
// ============================================================================
#include "rawr_agent_audit_driver.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "deep2/AgentToolRegistry.hpp"
#include "rawr_agent_dispatch.hpp"
#include "rawr_run_stream.hpp"

// The one-loop reply machinery (parser, prompts, history) is shared with
// run_agent_session; expose the minimal hooks needed by the driver.
#include "rawr_agent.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rawrxd {
namespace agent {

using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::AgentToolSurface;
using RawrXD::Agentic::ToolRequest;
using RawrXD::Agentic::ToolResult;
using rawrxd::runstream::RawrDeep2Runner;

namespace {

// Best-effort git HEAD SHA as human-readable source-tree evidence. The
// content hash remains the authority; this is provenance context.
std::string readGitHeadSha(const std::filesystem::path& ws) {
    const std::filesystem::path head = ws / ".git" / "HEAD";
    std::ifstream f(head);
    if (!f) return "(no-git)";
    std::string line;
    std::getline(f, line);
    if (line.rfind("ref: ", 0) == 0) {
        const std::filesystem::path ref =
            ws / ".git" / line.substr(5);
        std::ifstream rf(ref);
        if (!rf) return "(unresolved-ref)";
        std::string sha;
        std::getline(rf, sha);
        return sha;
    }
    return line;
}
// Adjudication-only tools: everything else is unregistered after the scan
// completes so the model physically cannot enumerate/build/test mid-review.
const char* kAdjudicationTools[] = {
    "audit-coverage", "audit-candidates", "audit-candidate-read",
    "audit-candidate-review", "file-read", "code-search", "symbol-find",
    "symbol-references", nullptr,
};

const char* kAdjudicationPrompt =
    "You are a code-audit candidate adjudicator inside the RawrXD runtime. "
    "A deterministic scanner has produced suspicious candidates from the "
    "repository. You review ONLY the candidates presented in this batch.\n\n"
    "PROTOCOL (strict):\n"
    "1. To call exactly ONE tool, reply with ONLY:\n"
    "   <tool>tool_name</tool>\n"
    "   <args>{\"param\":\"value\"}</args>\n"
    "2. When the batch is fully reviewed, reply with a one-paragraph summary "
    "of your verdicts (no tool tags).\n"
    "3. NEVER fabricate file contents or tool results.\n\n"
    "BATCH WORKFLOW (strict order):\n"
    "- audit.candidates {\"limit\":%u} to see this batch's pending candidates.\n"
    "- For EACH candidate: audit.candidate.read {\"id\":N} first. If the "
    "evidence is clear from the read, immediately "
    "audit.candidate.review {\"id\":N,\"verdict\":\"confirmed|false_positive|"
    "needs_runtime_proof\",\"note\":\"..\"}.\n"
    "- Only call file.read / code.search / symbol.find / symbol.references "
    "when a verdict genuinely needs more context.\n"
    "- Every candidate in this batch MUST receive a review verdict before "
    "your final summary. The runtime verifies this.\n\n";

std::string trim(std::string s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string excerpt(const std::string& s, size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    return s.substr(0, maxBytes) + "\n...[truncated " +
           std::to_string(s.size() - maxBytes) + " bytes]";
}

// Dirty-state evidence: is the working tree clean at HEAD?
bool gitTreeClean(const std::filesystem::path& ws) {
#ifdef _WIN32
    const std::string git = "C:\\Program Files\\Git\\cmd\\git.exe";
#else
    const std::string git = "git";
#endif
    std::string cmd = "\"" + git + "\" -C \"" + ws.string() +
                      "\" diff --quiet --stat";
#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) return false;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe)) { /* drain */ }
#ifdef _WIN32
    const int ec = _pclose(pipe);
#else
    const int ec = pclose(pipe);
#endif
    return ec == 0;
}

} // namespace

// ---------------------------------------------------------------------------
// One adjudication batch: compact model session over pending candidates.
// ---------------------------------------------------------------------------
static AuditBatchResult runAuditBatch(RawrDeep2Runner& runner,
                                       AuditLedger& ledger,
                                       AgentToolRegistry& authority,
                                       const AuditDriverOptions& opts,
                                       uint32_t batchIndex) {
    AuditBatchResult batch;
    batch.batchIndex = batchIndex;

    const AuditCounters before = ledger.counters();
    batch.candidatesIn = static_cast<uint32_t>(before.candidatesPending);
    // Compact per-batch context: system + batch directive.
    char promptHeader[1024];
    std::snprintf(promptHeader, sizeof(promptHeader),
                  kAdjudicationPrompt, opts.batchSize);
    const std::string systemPrompt = std::string(promptHeader);

    struct Turn { std::string tool, args, result; };
    std::vector<Turn> history;
    constexpr size_t kMaxHistory = 24;  // recent turns only per batch

    uint32_t modelTurns = 0;
    bool reachedFinal = false;
    std::string finalText;

    for (uint32_t step = 0; step < opts.maxStepsPerBatch; ++step) {
        ++modelTurns;

        std::ostringstream prompt;
        prompt << "<|im_start|>system\n" << systemPrompt << "<|im_end|>\n"
               << "<|im_start|>user\nReview this batch of pending audit "
                  "candidates now. Batch "
               << batchIndex << ".<|im_end|>\n";
        size_t from = history.size() > kMaxHistory
                          ? history.size() - kMaxHistory : 0;
        for (size_t i = from; i < history.size(); ++i) {
            prompt << "<|im_start|>assistant\n<tool>" << history[i].tool
                   << "</tool>\n<args>" << history[i].args
                   << "</args><|im_end|>\n"
                   << "<|im_start|>user\n[TOOL RESULT for "
                   << history[i].tool << "]\n" << history[i].result
                   << "<|im_end|>\n";
        }
        prompt << "<|im_start|>user\nContinue the batch: call exactly one "
                  "tool, or give your final batch summary when every "
                  "candidate has a verdict.<|im_end|>\n"
                  "<|im_start|>assistant\n";

        std::string replyText;
        bool stoppedOnImEnd = false;
        Deep2::GenerationOptions gen{};
        gen.maxTokens = opts.maxTokensPerStep;
        gen.temperature = 0.0f;
        gen.topK = 1;
        gen.topP = 1.0f;
        gen.repeatPenalty = 1.0f;
        gen.seed = 1;

        runner.reset();
        const auto genResult = runner.engine().generateStream(
            prompt.str(), gen,
            [&](int32_t, const std::string& piece) -> bool {
                replyText += piece;
                if (replyText.find("<|im_end|>") != std::string::npos) {
                    stoppedOnImEnd = true;
                    return false;
                }
                return true;
            });

        if (stoppedOnImEnd)
            replyText = replyText.substr(0, replyText.find("<|im_end|>"));

        const ProtocolParseResultForTest reply =
            parseModelReplyForTest(replyText);

        if (reply.isFinal) {
            reachedFinal = true;
            finalText = reply.tool.empty() ? trim(replyText) : reply.args;
            break;
        }
        if (!reply.isTool) {
            // Protocol error or empty: hard stop this batch.
            std::fprintf(stderr,
                         "[RAWR_AUDIT_BATCH] batch=%u protocol error at "
                         "step=%u\n",
                         batchIndex, step);
            break;
        }

        ToolRequest request;
        request.surface = AgentToolSurface::AgentCore;
        request.tool_id = reply.tool;
        request.stdin_text = reply.args;
        request.working_directory = ledger.workspaceRoot();

        const ToolResult toolResult = authority.invoke(request, {});
        if (toolResult.exit_code == 127) {
            ++batch.invalidToolAttempts;
        } else if (!toolResult.ok()) {
            ++batch.unrecoveredFailures;
        } else if (batch.invalidToolAttempts > 0) {
            ++batch.recoveredToolErrors;
        }

        std::ostringstream tr;
        tr << (toolResult.ok() ? toolResult.stdout_text
                               : toolResult.stderr_text);
        if (tr.str().empty()) tr << "(tool returned no output)";
        history.push_back({reply.tool, reply.args,
                           excerpt(tr.str(), 4096)});

        std::fprintf(stderr,
                     "[RAWR_AUDIT_BATCH] batch=%u step=%u tool=%s exit=%d "
                     "len=%zu\n",
                     batchIndex, step, reply.tool.c_str(),
                     toolResult.exit_code, tr.str().size());
    }

    // Ledger-derived accounting: never trust the model's claim of what it
    // reviewed — derive reviewed-delta from the durable counters.
    const AuditCounters after = ledger.counters();
    batch.candidatesDone = static_cast<uint32_t>(
        after.candidatesReviewed > before.candidatesReviewed
            ? after.candidatesReviewed - before.candidatesReviewed
            : 0);
    batch.candidatesRemaining = after.candidatesPending;
    batch.exitCode =
        (reachedFinal && batch.unrecoveredFailures == 0 &&
         batch.candidatesDone > 0)
            ? 0
            : 1;

    std::fprintf(stderr,
                 "RAWR_AUDIT_BATCH_RECEIPT\n"
                 "SCAN_EPOCH_SCHEMA=%u\n"
                 "BATCH_INDEX=%u\n"
                 "CANDIDATES_INPUT=%u\n"
                 "CANDIDATES_REVIEWED_DELTA=%u\n"
                 "CANDIDATES_REMAINING=%llu\n"
                 "MODEL_TURNS=%u\n"
                 "INVALID_TOOL_ATTEMPTS=%u\n"
                 "RECOVERED_TOOL_ERRORS=%u\n"
                 "UNRECOVERED_TOOL_FAILURES=%u\n"
                 "WRITE_ACTIONS=0\n"
                 "BATCH_EXIT=%d\n",
                 kCurrentEpochSchema,
                 batch.batchIndex, batch.candidatesIn, batch.candidatesDone,
                 static_cast<unsigned long long>(batch.candidatesRemaining),
                 modelTurns, batch.invalidToolAttempts,
                 batch.recoveredToolErrors, batch.unrecoveredFailures,
                 batch.exitCode);
    (void)finalText;
    return batch;
}

// ---------------------------------------------------------------------------
// The runtime-owned outer loop.
// ---------------------------------------------------------------------------
AuditE2EResult runAuditToCompletion(RawrDeep2Runner& runner,
                                    const std::filesystem::path& workspaceRoot,
                                    const AuditDriverOptions& opts) {
    AuditE2EResult e2e;

    AuditLedger ledger(workspaceRoot);
    const uint64_t enumerated = ledger.enumerateSources();
    const std::string sourceGitSha = readGitHeadSha(workspaceRoot);
    const bool sourceDirtyAtStart = !gitTreeClean(workspaceRoot);
    std::fprintf(stderr, "[RAWR_AUDIT_E2E] files_enumerated=%llu\n",
                 static_cast<unsigned long long>(enumerated));
    std::fprintf(stderr, "[RAWR_AUDIT_E2E] source_git_sha=%s dirty_at_start=%d\n",
                 sourceGitSha.c_str(), sourceDirtyAtStart ? 1 : 0);

    // Generation lifecycle — resume-first (RAWR_AUDIT_RESUME_001):
    //   1. try to LOAD a persisted generation matching the live tree
    //   2. if it matches, resume with prior verdicts intact (no rescan)
    //   3. if none matches, archive any stale generation and scan fresh
    bool resumed = false;
    if (ledger.resumeGeneration()) {
        ledger.refreshScanEpoch();
        if (ledger.generationMatchesLive()) {
            resumed = true;
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] GENERATION_LOADED=1 generation=%llu "
                         "prior_verdicts=%llu\n",
                         static_cast<unsigned long long>(
                             ledger.generation().generationId),
                         static_cast<unsigned long long>(
                             ledger.candidatesReviewedAtLoad()));
        } else {
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] persisted generation stale — "
                         "archiving and starting fresh\n");
            ledger.archiveGeneration("EPOCH_MISMATCH_AT_RESUME");
            ledger.enumerateSources();
        }
    } else {
        std::fprintf(stderr,
                     "[RAWR_AUDIT_E2E] no resumable generation — fresh scan "
                     "generation %llu\n",
                     static_cast<unsigned long long>(
                         ledger.generation().generationId));
    }
    const bool legacyArchived = ledger.generationSeqAtArchive() != 0;

    AgentToolRegistry authority;
    registerAuditToolProviders(authority, &ledger);
    {
        std::vector<std::string> names;
        for (const auto& d : authority.list()) names.push_back(d.id);
        setKnownToolNames(names);
    }

    // Phase 1: exhaustive scan (runtime decides; model not asked). A resumed
    // generation skips the rescan entirely.
    AuditCounters cov = ledger.counters();
    if (!resumed && (!cov.sourceScanComplete || ledger.candidateCount() == 0)) {
        ledger.runSourceScan();
        cov = ledger.counters();
        std::fprintf(stderr, "[RAWR_AUDIT_E2E] scan complete files_scanned=%llu "
                             "candidates=%llu epoch=%s\n",
                     static_cast<unsigned long long>(cov.filesScanned),
                     static_cast<unsigned long long>(cov.candidatesTotal),
                     ledger.scanEpoch().c_str());
    }
    // Persist the generation for crash/resume (durable snapshot).
    ledger.loadGeneration();

    // Phase 2: restrict the tool surface to adjudication only.
    for (const auto& d : authority.list()) {
        bool keep = false;
        for (int i = 0; kAdjudicationTools[i]; ++i)
            if (d.id == kAdjudicationTools[i]) { keep = true; break; }
        if (!keep) authority.unregisterTool(d.id);
    }
    {
        std::vector<std::string> names;
        for (const auto& d : authority.list()) names.push_back(d.id);
        setKnownToolNames(names);
    }

    // Phase 3: batch loop until CANDIDATES_PENDING=0 (runtime authority).
    const std::string scanEpochStart = ledger.scanEpoch();
    const uint64_t generationIdAtStart = ledger.generation().generationId;
    const uint64_t reviewedBeforeRun = ledger.counters().candidatesReviewed;
    uint32_t noProgressBatches = 0;
    bool haltedNoProgress = false;
    bool maxBatchesReached = false;
    bool staleSource = false;
    uint32_t batchIndex = 0;
    while (true) {
        cov = ledger.counters();
        if (cov.candidatesPending == 0) break;
        if (opts.maxBatches > 0 && batchIndex >= opts.maxBatches) {
            maxBatchesReached = true;
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] max_batches reached pending=%llu\n",
                         static_cast<unsigned long long>(cov.candidatesPending));
            break;
        }
        if (cov.toolFailures > 0) {
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] halting: durable tool failures=%llu\n",
                         static_cast<unsigned long long>(cov.toolFailures));
            break;
        }

        const uint64_t pendingBefore = cov.candidatesPending;

        // Batch-boundary integrity check: the live epoch must still match
        // the generation epoch. A mid-audit edit halts the run immediately.
        // Cost: one full-tree content hash (~seconds).
        ledger.refreshScanEpoch();
        if (!ledger.generationMatchesLive()) {
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] live epoch changed at batch boundary "
                         "— halting (STALE_SOURCE)\n");
            staleSource = true;
            break;
        }

        const AuditBatchResult b =
            runAuditBatch(runner, ledger, authority, opts, batchIndex);
        ++batchIndex;
        ++e2e.batches;
        e2e.invalidToolAttempts += b.invalidToolAttempts;
        e2e.recoveredToolErrors += b.recoveredToolErrors;
        e2e.unrecoveredFailures += b.unrecoveredFailures;

        // Monotonic progress: pending must strictly decrease, else count.
        const uint64_t pendingAfter = ledger.counters().candidatesPending;
        if (pendingAfter >= pendingBefore) {
            ++noProgressBatches;
            std::fprintf(stderr,
                         "[RAWR_AUDIT_E2E] batch %u made no progress "
                         "(pending %llu -> %llu); no-progress streak=%u\n",
                         batchIndex,
                         static_cast<unsigned long long>(pendingBefore),
                         static_cast<unsigned long long>(pendingAfter),
                         noProgressBatches);
            if (noProgressBatches >= 2) {
                haltedNoProgress = true;
                break;
            }
        } else {
            noProgressBatches = 0;
        }
    }

    // Phase 4: global receipt — the runtime mints it, never the model.
    const uint64_t reviewedBeforeBatch = reviewedBeforeRun;
    cov = ledger.counters();
    ledger.refreshScanEpoch();
    const std::string scanEpochEnd = ledger.scanEpoch();
    const bool epochMatch = scanEpochStart == scanEpochEnd;
    e2e.coverageComplete = ledger.coverageComplete() && epochMatch;
    ledger.writeSnapshot(workspaceRoot / ".rawr" / "audit_candidates.jsonl");
    ledger.loadGeneration();  // persist latest verdicts for the next process
    const bool sourceDirtyAtEnd = !gitTreeClean(workspaceRoot);

    const bool complete = cov.candidatesPending == 0;
    const bool ok = e2e.coverageComplete && epochMatch &&
                    e2e.unrecoveredFailures == 0 && complete &&
                    !haltedNoProgress && !staleSource;
    // Intentionally bounded/incomplete runs are INCOMPLETE, not FAIL: the
    // operator deliberately stopped short (--max-batches) or the source
    // tree changed mid-audit (stale candidates must NOT be silently
    // re-reviewed against a different tree).
    if (staleSource)
        e2e.status = "FAIL_STALE_SOURCE";
    else if (!complete)
        e2e.status = maxBatchesReached ? "INCOMPLETE" : "FAIL";
    else if (!epochMatch)
        e2e.status = "FAIL_STALE_SOURCE";
    else if (!ok)
        e2e.status = "FAIL";
    else
        e2e.status = "PASS";
    e2e.exitCode = ok ? 0 : 1;
    e2e.reportEmitted = complete && ok;

    std::fprintf(stderr,
                 "RAWR_IDE_AUDIT_E2E_001_RECEIPT\n"
                 "SCAN_EPOCH_SCHEMA=%u\n"
                 "SCAN_EPOCH_ALGO=%s\n"
                 "GENERATION_ID=%llu\n"
                 "GENERATION_LOADED=%d\n"
                 "GENERATION_ARCHIVED=%d\n"
                 "SOURCE_RESCAN=%d\n"
                 "LEGACY_CANDIDATES_MIGRATED=0\n"
                 "SOURCE_GIT_SHA=%s\n"
                 "SOURCE_DIRTY_AT_SCAN_START=%d\n"
                 "SOURCE_DIRTY_AT_COMPLETION=%d\n"
                 "SCAN_CHANGE_HASH_START=%s\n"
                 "SCAN_CHANGE_HASH_END=%s\n"
                 "SCAN_EPOCH_MATCH=%d\n"
                 "FILES_ENUMERATED=%llu\n"
                 "FILES_SCANNED=%llu\n"
                 "SOURCE_SCAN_COMPLETE=%d\n"
                 "CANDIDATES_TOTAL=%llu\n"
                 "CANDIDATES_REVIEWED_BEFORE=%llu\n"
                 "CANDIDATES_REVIEWED=%llu\n"
                 "CANDIDATES_PENDING=%llu\n"
                 "CONFIRMED_DEFECTS=%llu\n"
                 "FALSE_POSITIVES=%llu\n"
                 "NEEDS_RUNTIME_PROOF=%llu\n"
                 "INVALID_TOOL_ATTEMPTS=%u\n"
                 "RECOVERED_TOOL_ERRORS=%u\n"
                 "UNRECOVERED_TOOL_FAILURES=%u\n"
                 "FAKE_TOOL_RESULTS=0\n"
                 "WRITE_ACTIONS=0\n"
                 "MODEL_FALLBACK=0\n"
                 "AUDIT_BATCHES=%llu\n"
                 "NO_PROGRESS_BATCHES=%u\n"
                 "AUDIT_HALT_REASON=%s\n"
                 "REPORT_EMITTED=%d\n"
                 "COVERAGE_COMPLETE=%d\n"
                 "GEN_EXIT=%d\n"
                 "RAWR_IDE_AUDIT_E2E_001=%s\n",
                 kCurrentEpochSchema,
                 kEpochAlgorithm,
                 static_cast<unsigned long long>(generationIdAtStart),
                 resumed ? 1 : 0,
                 legacyArchived ? 1 : 0,
                 resumed ? 0 : 1,
                 sourceGitSha.c_str(),
                 sourceDirtyAtStart ? 1 : 0,
                 sourceDirtyAtEnd ? 1 : 0,
                 scanEpochStart.c_str(),
                 scanEpochEnd.c_str(),
                 epochMatch ? 1 : 0,
                 static_cast<unsigned long long>(cov.filesEnumerated),
                 static_cast<unsigned long long>(cov.filesScanned),
                 cov.sourceScanComplete ? 1 : 0,
                 static_cast<unsigned long long>(cov.candidatesTotal),
                 static_cast<unsigned long long>(reviewedBeforeBatch),
                 static_cast<unsigned long long>(cov.candidatesReviewed),
                 static_cast<unsigned long long>(cov.candidatesPending),
                 static_cast<unsigned long long>(cov.confirmedDefects),
                 static_cast<unsigned long long>(cov.falsePositives),
                 static_cast<unsigned long long>(cov.needsRuntimeProof),
                 e2e.invalidToolAttempts,
                 e2e.recoveredToolErrors,
                 e2e.unrecoveredFailures,
                 static_cast<unsigned long long>(e2e.batches),
                 noProgressBatches,
                 haltedNoProgress ? "NO_PROGRESS"
                                  : (maxBatchesReached ? "MAX_BATCHES"
                                                       : (staleSource ? "STALE_SOURCE" : "NONE")),
                 e2e.reportEmitted ? 1 : 0,
                 e2e.coverageComplete ? 1 : 0,
                 e2e.exitCode,
                 e2e.status.c_str());
    std::fflush(stderr);
    return e2e;
}

} // namespace agent
} // namespace rawrxd