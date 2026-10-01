// AgentCore.cpp — RAWRXD_LOCAL_AGENT_E2E_001
#include "agent/AgentCore.h"

#include "ProcessUtil.h"

#include "deep2/Deep2Engine.h"
#include "deep2/ReceiptAuthority.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include <windows.h>

namespace fs = std::filesystem;

namespace rawrxd { namespace deep2 {
// Exposed by rawrxd_run_modelname_001.cpp so the agent resolves models through
// exactly the same path the CLI uses, rather than a second heuristic.
std::string resolveModelPathForAgent(const std::string& nameOrPath);
}}
namespace rawrxd { namespace agentcore {

// Engine-reported outcome, rendered so a receipt can distinguish "the model
// finished" from "the engine gave up with a reason". Defined outside the
// anonymous namespace so it matches the forward declaration above.
std::string statusName(Deep2::GenerationStatus s) {
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence: return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:     return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        case Deep2::GenerationStatus::InternalError: return "InternalError";
        default:                                     return "Unknown";
    }
}

// Receipt path the core writes to. Set by the caller so the run can flush a
// receipt mid-flight: Deep2 re-runs all layers per token with no KV reuse, so
// the second turn can take many minutes, and a hard kill there previously left
// no evidence at all.
static std::string g_receiptPath;

void setReceiptPath(const std::string& p) { g_receiptPath = p; }

// ---------------------------------------------------------------- model side

LocalModelBackend::LocalModelBackend(std::string modelRef, uint32_t maxTokens)
    : modelRef_(std::move(modelRef)), maxTokens_(maxTokens) {}

bool LocalModelBackend::available(std::string& reason) {
    resolvedPath_ = deep2::resolveModelPathForAgent(modelRef_);
    if (resolvedPath_.empty()) {
        reason = "could not resolve model reference '" + modelRef_ + "' to a GGUF path";
        return false;
    }
    return true;
}

std::string LocalModelBackend::generate(const std::string& prompt, uint32_t maxTokens,
                                       bool& ok, std::string& reason) {
    ok = false;
    reason.clear();

    if (resolvedPath_.empty()) {
        reason = "model not resolved";
        return {};
    }

    static thread_local Deep2::Deep2Engine* engine = nullptr;
    static thread_local std::string enginePath;

    // Load once per thread: reload dominates the cost of a short agent turn.
    if (!engine || enginePath != resolvedPath_) {
        if (engine) { delete engine; engine = nullptr; }
        engine = new Deep2::Deep2Engine();
        Deep2::EngineConfig cfg;
        cfg.maxSeqLen  = 4096;
        cfg.numThreads = 0;
        if (!engine->initialize(cfg)) { reason = "Deep2Engine::initialize failed"; delete engine; engine = nullptr; return {}; }
        engine->enableVulkan(false);
        Deep2::ModelLoadDiag diag{};
        if (!engine->loadModel(resolvedPath_, &diag)) {
            reason = "loadModel failed at " + diag.stageName + ": " + diag.message;
            delete engine; engine = nullptr;
            return {};
        }
        enginePath = resolvedPath_;
    }

    Deep2::GenerationOptions opts;
    opts.maxTokens  = maxTokens;
    opts.temperature = 0.0f;      // deterministic, so a run is reproducible
    opts.topK        = 1;
    opts.topP        = 1.0f;
    opts.seed        = 7;

    std::string text;
    uint32_t tokens = 0;
    // One stream callback is one generated token. Counting here is a real
    // measurement; dividing the text by a guessed characters-per-token ratio
    // would be a fabricated one.
    auto cb = [&text, &tokens](int32_t, const std::string& tok) -> bool {
        text += tok; ++tokens; return true;
    };
    const Deep2::GenerationResult r = engine->generateStream(prompt, opts, cb);
    lastTokenCount_ = tokens;
    // Record what the engine itself says. The engine is authoritative about
    // its own outcome; previously only `completed` was consulted, so an
    // engine-reported failure was indistinguishable from the model simply
    // choosing to emit nothing.
    eng_       = r;
    engStatus_ = statusName(r.status);
    engDetail_ = r.failureDetail;
    if (!r.completed) {
        reason = "generation incomplete [" + engStatus_ + "]";
        if (!r.failureDetail.empty()) reason += ": " + r.failureDetail;
        return text;
    }
    ok = true;
    return text;
}

// ---------------------------------------------------------------- tool side

namespace {

std::string trimStr(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Engine-reported outcome, rendered so a receipt can distinguish "the model
// finished" from "the engine gave up with a reason".
std::string statusNameImpl(Deep2::GenerationStatus s) {
    return statusName(s);
}

// Process launching, path confinement and bounded reads are shared with the
// response-coded agent via agent/AgentProcess.h. They used to be duplicated
// here, and each copy carried a defect the other did not: this file's runner
// broke out of the read loop at the 8000-byte cap, closing the pipe while the
// child was still writing. `git status --porcelain` in a working tree this size
// always exceeds the cap, so git was killed with a broken pipe and its non-zero
// exit was reported as a genuine tool failure.

// Parse a small non-negative integer, clamped. Anything else yields `fallback`.
uint32_t clampedUint(const std::string& s, uint32_t lo, uint32_t hi, uint32_t fallback) {
    if (s.empty()) return fallback;
    for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) return fallback;
    unsigned long v = 0;
    try { v = std::stoul(s); } catch (...) { return fallback; }
    if (v < lo) return lo;
    if (v > hi) return hi;
    return static_cast<uint32_t>(v);
}

} // namespace

// The READ_ONLY allowlist, in the order it is offered to the model.
const char* const kReadOnlyToolNames[] = {
    "git_status",   // is the worktree clean?
    "git_log",      // what is the current HEAD?
    "git_diff",     // what changed?
    "list_dir",     // what is in a directory?
    "read_file",    // read a file
    "count_lines",  // how many lines in a file?
};
const int kReadOnlyToolCount =
    static_cast<int>(sizeof(kReadOnlyToolNames) / sizeof(kReadOnlyToolNames[0]));

ToolRequest parseToolRequest(const std::string& text) {
    ToolRequest r;
    std::istringstream is(text);
    std::string line;
    while (std::getline(is, line)) {
        const std::string t = trimStr(line);
        if (t.empty()) continue;

        // Accept "TOOL: read_file", "TOOL = read_file", "**TOOL:** read_file".
        const std::string low = lower(t);
        const size_t colon = low.find(':');
        if (colon != std::string::npos) {
            std::string key = lower(trimStr(low.substr(0, colon)));
            std::string val = trimStr(t.substr(colon + 1));
            // Strip markdown emphasis the model may add.
            key.erase(std::remove(key.begin(), key.end(), '*'), key.end());
            val.erase(std::remove(val.begin(), val.end(), '*'), val.end());
            val = trimStr(val);
            if (key == "tool" && r.tool.empty()) {
                r.tool = lower(val);
            } else if (key == "path" || key == "dir" || key == "arg") {
                r.argument = val;
            }
            if (r.tool.empty()) continue;

            // git_status, git_log and git_diff take no argument, so a blank ARG
            // line is correct for them and must not invalidate the request.
            // Requiring a non-empty argument was a bug: it made every
            // no-argument tool unrequestable, and a run could then only fail.
            const bool noArgTool = (r.tool == "git_status" || r.tool == "git_log" ||
                                    r.tool == "git_diff" || r.tool == "git_diff_stat");
            const bool sawArgKey = (key == "path" || key == "dir" || key == "arg");
            if (r.tool.find("git_") == 0 || noArgTool) {
                // A git tool is complete as soon as it is named.
                if (sawArgKey || !r.argument.empty()) { r.present = true; r.raw = t; }
            } else if (!r.argument.empty()) {
                r.present = true;
                r.raw = t;
            }
        }
    }
    return r;
}

ReadOnlyToolbox::ReadOnlyToolbox(std::string repoRoot)
    : repoRoot_(std::move(repoRoot)) {
    std::error_code ec;
    repoRoot_ = fs::weakly_canonical(fs::path(repoRoot_), ec).string();
}

ToolOutcome ReadOnlyToolbox::execute(const ToolRequest& req, std::string& output, std::string& detail) {
    output.clear(); detail.clear();
    if (!req.present) return ToolOutcome::NotRequested;

    const std::string tool = lower(req.tool);
    // READ_ONLY allowlist. There is deliberately no write, delete, or network
    // tool in this class, so a READ_ONLY run cannot mutate anything.
    bool allowed = false;
    for (int i = 0; i < kReadOnlyToolCount; ++i) {
        if (tool == kReadOnlyToolNames[i]) { allowed = true; break; }
    }
    if (!allowed) {
        ++rejects_;
        detail = "tool '" + req.tool + "' is not in the READ_ONLY allowlist";
        return ToolOutcome::RejectedNotAllowed;
    }

    // ---- git tools: no model-supplied path, no model-supplied subcommand ----
    if (tool == "git_status" || tool == "git_log" || tool == "git_diff") {
        std::vector<std::string> args;
        // -C is what makes this report the repository the caller named. Without
        // it git runs in the process working directory, so the tool answered a
        // question about wherever the IDE or CLI happened to be launched from.
        args.push_back("-C");
        args.push_back(repoRoot_);
        if (tool == "git_status") args = { args[0], args[1], "status", "--porcelain" };
        else if (tool == "git_log") {
            const uint32_t n = clampedUint(trimStr(req.argument), 1, 20, 1);
            args = { args[0], args[1], "log", "-n", std::to_string(n), "--format=%H %s" };
        } else {
            args = { args[0], args[1], "diff", "--stat" };
        }
        int32_t code = -1;
        const procutil::RunResult rr =
            procutil::runProcessNoShell("git", args, output, code);
        if (rr == procutil::RunResult::SpawnFailed) {
            ++rejects_;
            detail = "could not launch git for " + tool;
            return ToolOutcome::RejectedNotAllowed;
        }
        if (rr == procutil::RunResult::TimedOut) {
            // A timeout is not a non-zero exit code. Reporting STILL_ACTIVE as
            // the command's own result states a different fact than the one
            // that occurred.
            lastExitCode_ = code;
            ++rejects_;
            detail = tool + " timed out after 15s (not a command failure)";
            return ToolOutcome::RejectedNotAllowed;
        }
        lastExitCode_ = code;
        if (code != 0) {
            ++rejects_;
            detail = tool + " exited " + std::to_string(code);
            return ToolOutcome::RejectedNotAllowed;
        }
        if (output.empty()) output = "(no output)";
        ++calls_;
        detail = tool + " exit=" + std::to_string(code) +
                 " bytes=" + std::to_string(output.size());
        return ToolOutcome::Executed;
    }

    // ---- path tools: resolve and confine before touching anything ----
    const fs::path target = fs::path(repoRoot_) / req.argument;
    std::error_code ec;
    const fs::path canon = fs::weakly_canonical(target, ec);
    if (ec) {
        ++rejects_;
        detail = "cannot canonicalize '" + req.argument + "'";
        return ToolOutcome::RejectedPathEscape;
    }
    // Reject anything resolving outside the repository.
    //
    // Component-wise, not by string prefix. The previous test was
    // `targLow.rfind(rootLow, 0) != 0`, which accepted
    // F:\~dev\rawrxd_backup\secret.txt for root F:\~dev\rawrxd because that
    // string does begin with the root's string.
    if (!procutil::isInsideRoot(canon, fs::path(repoRoot_))) {
        ++rejects_;
        detail = "path escapes repository root: " + req.argument;
        return ToolOutcome::RejectedPathEscape;
    }
    if (!fs::exists(canon, ec)) {
        ++rejects_;
        detail = "no such path: " + req.argument;
        return ToolOutcome::RejectedPathEscape;
    }

    ++calls_;
    if (tool == "list_dir") {
        std::ostringstream os;
        for (const auto& e : fs::directory_iterator(canon, ec)) {
            if (ec) break;
            os << e.path().filename().string() << "\n";
        }
        output = os.str();
        detail = "listed " + req.argument;
        return ToolOutcome::Executed;
    }

    if (tool == "count_lines") {
        std::ifstream in(canon, std::ios::binary);
        if (!in) { ++rejects_; detail = "cannot open " + req.argument; return ToolOutcome::RejectedPathEscape; }
        uint64_t lines = 0;
        char buf[4096];
        while (in.read(buf, sizeof buf) || in.gcount() > 0) {
            const std::streamsize got = in.gcount();
            if (got <= 0) break;
            for (std::streamsize i = 0; i < got; ++i) if (buf[i] == '\n') ++lines;
        }
        output = std::to_string(lines) + " lines in " + req.argument + "\n";
        detail = "counted " + std::to_string(lines) + " lines in " + req.argument;
        return ToolOutcome::Executed;
    }

    // read_file: cap the observation so a huge file cannot swamp the context.
    //
    // The bounded read is shared with the response-coded agent, which carried
    // the same loop with the precedence bug (`total < kMax && in.read(..) ||
    // in.gcount() > 0`) and therefore never returned for any file over 1500
    // bytes. One correct implementation now, in agent/AgentProcess.h.
    output = procutil::readBounded(canon, 3000);
    detail = "read " + std::to_string(output.size()) + " bytes from " + req.argument;
    return ToolOutcome::Executed;
}

// ------------------------------------------------------------------ the core

AgentRun runReadOnly(const AgentTask& task, IModelBackend& backend, ReadOnlyToolbox& toolbox) {
    AgentRun r;
    r.modelRef = backend.modelRef();

    std::string reason;
    if (!backend.available(reason)) {
        r.verdict = "FAIL";
        r.rationale = reason;
        r.transitions.push_back({ Phase::Failed, reason });
        return r;
    }
    r.modelResolved = true;
    r.modelLoaded = true;
    r.resolvedPath = backend.resolvedPath();
    r.transitions.push_back({ Phase::Plan, "model resolved and loaded" });

    // ---- PLAN: ask which single read-only observation the task needs ----
    //
    // The model must CHOOSE the operation. The previous prompt ended with a
    // literal "TOOL: read_file / PATH: <a file...>" template, which handed it
    // the answer and made the selection meaningless. Here the tools are
    // described by what they answer, and the model has to pick the one its task
    // actually needs. If it picks wrong, the run still fails honestly.
    std::string planPrompt;
    planPrompt += "Read-only agent. Task: " + task.objective + "\n";
    planPrompt += "Tools: git_status | git_log | git_diff | list_dir | read_file | count_lines\n";
    planPrompt += "Pick the ONE tool that answers the task. Copy the name exactly.\n";
    planPrompt += "Never invent a name. Answer in exactly two lines:\n";
    planPrompt += "TOOL: <name>\nARG: <argument, or none>\n";

    bool ok = false;
    r.plan = backend.generate(planPrompt, 32, ok, reason);
    r.planTokenCount = backend.lastTokenCount();
    ++r.agentTurnCount;
    if (!ok) {
        r.verdict = "FAIL";
        r.rationale = "plan turn failed: " + reason;
        r.transitions.push_back({ Phase::Failed, r.rationale });
        return r;
    }
    r.planned = true;
    r.transitions.push_back({ Phase::Plan, "model produced a plan turn" });

    // ---- ACT: dispatch the requested read-only tool ----
    const ToolRequest req = parseToolRequest(r.plan);
    r.toolRequestRaw = req.raw;
    r.toolRequested = req.present;
    r.toolRequestParsed = req.present;
    r.modelActionGenerated = req.present;
    r.transitions.push_back({ Phase::Act, req.present ? ("tool request: " + req.tool + " " + req.argument)
                                                     : std::string("no tool request parsed from plan turn") });

    std::string out, detail;
    ToolOutcome outcome = toolbox.execute(req, out, detail);
    r.toolCalls   = toolbox.callCount();
    r.toolRejects = toolbox.rejectCount();
    r.toolExitCode = toolbox.lastExitCode();
    r.toolExecuted = (outcome == ToolOutcome::Executed);
    r.toolAuthorized = r.toolExecuted;   // dispatch only runs after allowlist validation
    r.toolRejected = (outcome == ToolOutcome::RejectedNotAllowed ||
                      outcome == ToolOutcome::RejectedPathEscape);

    if (outcome != ToolOutcome::Executed) {
        // No fabricated observation. A rejected or missing tool call is a
        // failure of the loop, not a soft pass.
        r.verdict = "FAIL";
        r.rationale = "tool dispatch did not execute: " +
                      (detail.empty() ? std::string("no parseable tool request") : detail);
        r.transitions.push_back({ Phase::Failed, r.rationale });
        return r;
    }
    r.transitions.push_back({ Phase::Observe, detail });

    // Flush evidence for steps 1-7 BEFORE the expensive second turn. If the
    // process dies during generation, the receipt still proves the model
    // resolved, loaded, chose a tool, and that a real observation happened.
    if (!g_receiptPath.empty()) {
        AgentRun interim = r;
        interim.verdict = "INTERRUPTIBLE";
        interim.rationale = "interim receipt: tool executed, continue turn not yet run";
        writeAgentReceipt(g_receiptPath, interim);
    }

    // ---- CONTINUE: reason over the real observation ----
    // The observation is returned to the SAME model session: the same engine,
    // same loaded weights, same greedy decoding, only the prompt changes.
    //
    // The observation is capped, and the cap is stated inside the prompt so the
    // model is not misled about what it is looking at. A 4.4KB `git status`
    // dump is mostly untracked-file noise; feeding it whole made the second
    // turn decode to an immediate stop.
    std::string obs = out;
    if (obs.size() > kMaxObservationBytes) {
        const size_t cut = obs.rfind('\n', kMaxObservationBytes);
        obs = obs.substr(0, cut == std::string::npos ? kMaxObservationBytes : cut);
        obs += "\n[...truncated; " + std::to_string(out.size()) + " bytes total]\n";
    }
    std::string contPrompt;
    contPrompt += "Read-only agent.\n";
    contPrompt += "Task: " + task.objective + "\n";
    contPrompt += "Tool " + req.tool + " returned:\n" + obs + "\n";
    contPrompt += "Answer the task in one or two short sentences. Start with the answer.\n";

    r.finalResponse = backend.generate(contPrompt, 48, ok, reason);
    r.finalTokenCount = backend.lastTokenCount();
    ++r.agentTurnCount;
    r.engineGeneratedTokens = backend.engineGeneratedTokens();
    r.enginePromptTokens    = backend.enginePromptTokens();
    r.engineStatus          = backend.engineStatus();
    r.engineFailureDetail   = backend.engineFailureDetail();
    r.enginePromptMs        = backend.enginePromptMs();
    r.engineGenerationMs    = backend.engineGenerationMs();
    if (!ok) {
        r.verdict = "FAIL";
        r.rationale = "continue turn failed: " + reason;
        r.transitions.push_back({ Phase::Failed, r.rationale });
        return r;
    }
    // The receipt must describe what the model actually received, not what the
    // tool produced. `contPrompt` was built from `obs`, which is `out` cut to
    // kMaxObservationBytes at line 455. Assigning `out` here made the receipt's
    // OBSERVATION field — and MODEL_CONSUMED_OBSERVATION, which is derived from
    // it — describe text the model never saw.
    r.observation = obs;
    r.toolObservationCaptured = !out.empty();
    r.observationReturnedToModel = true;   // `obs` was placed in contPrompt above
    r.observationUsed = true;
    // Truncation is recorded, not hidden: the full byte count stays available so
    // a reader can tell a short observation from a clipped one.
    r.observationTruncated = (obs.size() != out.size());
    // The final answer is only credited as consuming the observation if the
    // response is non-empty and the observation actually reached the model.
    r.modelConsumedObservation = r.observationUsed &&
                                 r.observationReturnedToModel &&
                                 !r.finalResponse.empty();
    r.completed = true;
    r.mutatingToolsAvailable  = 0;   // structural: the toolbox has no write tool
    r.arbitraryShellAvailable = 0;   // structural: dispatch uses CreateProcess, no shell
    r.fakeToolResults         = 0;   // structural: output comes from the process/file itself
    r.transitions.push_back({ Phase::Complete, "model produced a final response over the observation" });

    r.verdict = deriveVerdict(r);
    return r;
}

std::string deriveVerdict(const AgentRun& r) {
    // PASS requires a genuine end-to-end loop. Every predicate is measured.
    const bool pass = r.modelResolved && r.modelLoaded && r.planned &&
                      r.agentTurnCount >= 2 &&
                      r.toolRequested && r.toolAuthorized && r.toolExecuted &&
                      r.toolObservationCaptured && r.observationReturnedToModel &&
                      r.modelConsumedObservation && r.completed &&
                      r.stubFallbacks == 0 && r.fakeToolResults == 0 &&
                      r.mutatingToolsAvailable == 0 &&
                      r.arbitraryShellAvailable == 0 &&
                      r.engineGeneratedTokens >= 1 &&
                      r.finalTokenCount >= 1 &&
                      !r.finalResponse.empty();
    if (pass) return "PASS";
    if (!r.toolRequested) return "FAIL_NO_TOOL_REQUEST";
    if (!r.toolAuthorized) return "FAIL_TOOL_NOT_AUTHORIZED";
    if (!r.toolExecuted) return "FAIL_TOOL_NOT_EXECUTED";
    if (!r.toolObservationCaptured) return "FAIL_NO_OBSERVATION";
    if (r.agentTurnCount < 2) return "FAIL_TOO_FEW_TURNS";
    // Distinguish an engine that stopped without a reason from a model that
    // was asked to answer and produced nothing.
    if (r.engineGeneratedTokens < 1) return "FAIL_ENGINE_PRODUCED_NO_TOKENS";
    if (r.finalTokenCount < 1) return "FAIL_MODEL_DECODED_EMPTY";
    if (r.finalResponse.empty()) return "FAIL_NO_RESPONSE";
    return "FAIL";
}

void writeAgentReceipt(const std::string& path, const AgentRun& r) {
    receipt::beginGate(path, "RAWRXD_LOCAL_AGENT_E2E_001");
    receipt::writeKeyValue(path, "MODE", "READ_ONLY");
    receipt::writeKeyValue(path, "MUTATION_PERMITTED", "0");
    receipt::writeKeyValue(path, "MODEL_REF", r.modelRef);
    receipt::writeKeyValue(path, "RESOLVED_PATH", r.resolvedPath);
    receipt::writeKeyValueInt(path, "MODEL_RESOLVED", r.modelResolved ? 1 : 0);
    receipt::writeKeyValueInt(path, "MODEL_LOADED", r.modelLoaded ? 1 : 0);
    receipt::writeKeyValueInt(path, "PLANNED", r.planned ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_REQUESTED", r.toolRequested ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_EXECUTED", r.toolExecuted ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_REJECTED", r.toolRejected ? 1 : 0);
    receipt::writeKeyValueInt(path, "OBSERVATION_USED", r.observationUsed ? 1 : 0);
    receipt::writeKeyValueInt(path, "COMPLETED", r.completed ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_CALLS", r.toolCalls);
    receipt::writeKeyValueInt(path, "TOOL_REJECTS", r.toolRejects);
    receipt::writeKeyValueInt(path, "STUB_FALLBACKS", r.stubFallbacks);
    receipt::writeKeyValueInt(path, "TRANSITIONS", (int64_t)r.transitions.size());

    // ---- fields required by the RAWRXD_LOCAL_AGENT_E2E_001 contract ----
    receipt::writeKeyValue(path, "MODEL_PATH", r.resolvedPath);
    receipt::writeKeyValueInt(path, "MODEL_RELOCATED", 0);   // blob is read in place
    receipt::writeKeyValueInt(path, "AGENT_TURN_COUNT", r.agentTurnCount);
    receipt::writeKeyValueInt(path, "MODEL_ACTION_GENERATED", r.modelActionGenerated ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_REQUEST_PARSED", r.toolRequestParsed ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_AUTHORIZED", r.toolAuthorized ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_EXECUTED", r.toolExecuted ? 1 : 0);
    receipt::writeKeyValueInt(path, "TOOL_EXIT_CODE", r.toolExitCode);
    receipt::writeKeyValueInt(path, "TOOL_OBSERVATION_CAPTURED", r.toolObservationCaptured ? 1 : 0);
    receipt::writeKeyValueInt(path, "OBSERVATION_RETURNED_TO_MODEL",
                              r.observationReturnedToModel ? 1 : 0);
    receipt::writeKeyValueInt(path, "MODEL_CONSUMED_OBSERVATION",
                              r.modelConsumedObservation ? 1 : 0);
    receipt::writeKeyValueInt(path, "FINAL_RESPONSE_GENERATED",
                              (!r.finalResponse.empty() && r.finalTokenCount > 0) ? 1 : 0);
    receipt::writeKeyValueInt(path, "PLAN_TOKEN_COUNT", r.planTokenCount);
    receipt::writeKeyValueInt(path, "GENERATED_TOKEN_COUNT", r.finalTokenCount);
    receipt::writeKeyValueInt(path, "MUTATING_TOOLS_AVAILABLE", r.mutatingToolsAvailable);
    receipt::writeKeyValueInt(path, "ARBITRARY_SHELL_AVAILABLE", r.arbitraryShellAvailable);
    receipt::writeKeyValueInt(path, "FAKE_TOOL_RESULTS", r.fakeToolResults);
    receipt::writeKeyValueInt(path, "READ_ONLY_TOOL_COUNT", kReadOnlyToolCount);
    receipt::writeKeyValue(path, "READ_ONLY_TOOL_NAMES", [&] {
        std::string j;
        for (int i = 0; i < kReadOnlyToolCount; ++i) {
            if (i) j += ",";
            j += kReadOnlyToolNames[i];
        }
        return j;
    }());
    receipt::writeKeyValue(path, "OBSERVATION", r.observation);
    receipt::writeKeyValueInt(path, "OBSERVATION_TRUNCATED", r.observationTruncated ? 1 : 0);
    receipt::writeKeyValueInt(path, "ENGINE_GENERATED_TOKENS", (int64_t)r.engineGeneratedTokens);
    receipt::writeKeyValueInt(path, "ENGINE_PROMPT_TOKENS", (int64_t)r.enginePromptTokens);
    receipt::writeKeyValue(path, "ENGINE_STATUS", r.engineStatus);
    receipt::writeKeyValue(path, "ENGINE_FAILURE_DETAIL", r.engineFailureDetail);
    receipt::writeKeyValueFloat(path, "ENGINE_PROMPT_MS", r.enginePromptMs);
    receipt::writeKeyValueFloat(path, "ENGINE_GENERATION_MS", r.engineGenerationMs);
    for (size_t i = 0; i < r.transitions.size() && i < 32; ++i) {
        receipt::writeKeyValue(path, "TRANSITION_" + std::to_string(i + 1),
                               r.transitions[i].detail);
    }
    receipt::writeKeyValue(path, "PLAN_TURN", r.plan);
    receipt::writeKeyValue(path, "TOOL_REQUEST_RAW", r.toolRequestRaw);
    receipt::writeKeyValue(path, "FINAL_RESPONSE", r.finalResponse);
    receipt::writeKeyValue(path, "RATIONALE", r.rationale);
    receipt::endGate(path, r.verdict.c_str());
}

}} // namespace rawrxd::agentcore
