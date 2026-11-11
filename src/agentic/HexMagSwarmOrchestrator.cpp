// =============================================================================
// HexMagSwarmOrchestrator.cpp - Unified Multi-Agent Coding System Implementation
// =============================================================================
// Pipeline: User request -> Planning -> Parallel execution -> Verification -> Result
//
// Components wired:
//   SubAgentManager          - subagent lifecycle, chains, swarms
//   AgentOrchestrator        - agentic loop / tool dispatch
//   CEOAgent                 - autonomous engineering / planning
//   AdvancedAgentCoordinator - load balancing, health, deps, priority, scaling
//   Deep2Engine              - native inference (offline, no external models)
//   NativeToolExecutor       - real filesystem / compiler / linker / test / shell
//   HexMagRepeatTuner        - 7 strategies, 10 specialists, failure classes
// =============================================================================

#include "HexMagSwarmOrchestrator.hpp"
#include "agent_history.h"
#include "agent_policy.h"
#include "agentic_autonomous_config.h"
#include "hexmag_resilience_bridge.hpp"
#include "../Deep2Engine.h"
#include "ToolRegistry.hpp"
#include "AgentOllamaClient.h"
#include "FIMPromptBuilder.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace RawrXD {
namespace HexMag {

// =============================================================================
// Concrete Native Tool Executor (real filesystem/process operations)
// =============================================================================
class RealNativeToolExecutor : public NativeToolExecutor {
public:
    RealNativeToolExecutor() = default;

    bool readFile(const std::string& path, std::string& content) override {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        std::ostringstream ss;
        ss << f.rdbuf();
        content = ss.str();
        return true;
    }

    bool writeFile(const std::string& path, const std::string& content) override {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        std::ofstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        f << content;
        return f.good();
    }

    bool listDir(const std::string& path, std::vector<std::string>& entries) override {
        std::error_code ec;
        if (!std::filesystem::is_directory(path, ec)) return false;
        for (const auto& e : std::filesystem::directory_iterator(path, ec)) {
            std::ostringstream ss;
            ss << (e.is_directory() ? "[DIR] " : "[FILE] ") << e.path().filename().string();
            entries.push_back(ss.str());
        }
        return !ec;
    }

    bool grepFiles(const std::string& pattern, const std::string& path, std::string& results) override {
        std::error_code ec;
        std::vector<std::string> hits;
        std::regex re;
        try { re = std::regex(pattern, std::regex::icase); } catch (...) { return false; }
        std::filesystem::path base = path.empty() ? std::filesystem::path(".") : std::filesystem::path(path);
        for (const auto& entry : std::filesystem::recursive_directory_iterator(base, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_regular_file()) continue;
            std::ifstream f(entry.path());
            if (!f.is_open()) continue;
            std::string line;
            int lineNo = 0;
            while (std::getline(f, line)) {
                ++lineNo;
                if (std::regex_search(line, re)) {
                    std::ostringstream os;
                    os << entry.path().string() << ":" << lineNo << ": " << line;
                    hits.push_back(os.str());
                    if (hits.size() >= 100) break;
                }
            }
            if (hits.size() >= 100) break;
        }
        std::ostringstream os;
        os << "Grep Results (" << hits.size() << " matches for \"" << pattern << "\"):\n";
        for (const auto& h : hits) os << h << "\n";
        results = os.str();
        return true;
    }

    bool searchFiles(const std::string& query, const std::string& path, std::string& results) override {
        std::error_code ec;
        std::filesystem::path base = path.empty() ? std::filesystem::path(".") : std::filesystem::path(path);
        std::vector<std::string> hits;
        std::string q = query;
        std::transform(q.begin(), q.end(), q.begin(), ::tolower);
        for (const auto& entry : std::filesystem::recursive_directory_iterator(base, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_regular_file()) continue;
            std::string fn = entry.path().filename().string();
            std::transform(fn.begin(), fn.end(), fn.begin(), ::tolower);
            if (fn.find(q) != std::string::npos) {
                hits.push_back("MATCH (filename): " + entry.path().string());
                continue;
            }
            std::ifstream f(entry.path(), std::ios::binary);
            if (!f.is_open()) continue;
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            std::transform(content.begin(), content.end(), content.begin(), ::tolower);
            if (content.find(q) != std::string::npos) {
                hits.push_back("MATCH (content): " + entry.path().string());
            }
            if (hits.size() >= 100) break;
        }
        std::ostringstream os;
        os << "Search Results (" << hits.size() << " matches for \"" << query << "\"):\n";
        for (const auto& h : hits) os << h << "\n";
        results = os.str();
        return true;
    }

    bool referenceSymbol(const std::string& symbol, std::string& results) override {
        std::error_code ec;
        std::vector<std::string> hits;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(".", std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!entry.is_regular_file()) continue;
            std::string ext = entry.path().extension().string();
            if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".c") continue;
            std::ifstream f(entry.path());
            if (!f.is_open()) continue;
            std::string line;
            int lineNo = 0;
            while (std::getline(f, line)) {
                ++lineNo;
                if (line.find(symbol) != std::string::npos) {
                    std::ostringstream os;
                    os << (line.find(symbol + " ") == 0 || line.find(symbol + "(") != std::string::npos
                              ? "[DEF/USE] " : "[USE] ")
                       << entry.path().string() << ":" << lineNo << ": " << line;
                    hits.push_back(os.str());
                    if (hits.size() >= 50) break;
                }
            }
            if (hits.size() >= 50) break;
        }
        std::ostringstream os;
        os << "Symbol References for '" << symbol << "' (" << hits.size() << "):\n";
        for (const auto& h : hits) os << h << "\n";
        results = os.str();
        return true;
    }

    bool compile(const std::string& target, const std::string& config, std::string& output) override {
        if (!m_nativeCompilerOk) return false;
        std::string cmd = "universal_compiler.exe \"" + target + "\" " + (config == "Debug" ? "-g " : "-O2 ") +
                          "-o \"" + target + ".exe\" 2>&1";
        return runProcessCapture(cmd, output);
    }

    bool runBuild(const std::string& target, const std::string& config, std::string& output) override {
#ifdef _WIN32
        std::string cmd = "cmake --build build-ninja --target " + target + " 2>&1";
        return runProcessCapture(cmd, output);
#else
        std::string cmd = "cmake --build build --target " + target + " 2>&1";
        return runProcessCapture(cmd, output);
#endif
    }

    bool cleanBuild(const std::string& target, std::string& output) override {
#ifdef _WIN32
        std::string cmd = "cmake --build build-ninja --target clean 2>&1";
        return runProcessCapture(cmd, output);
#else
        std::string cmd = "cmake --build build --target clean 2>&1";
        return runProcessCapture(cmd, output);
#endif
    }

    bool runTests(const std::string& suite, std::string& output) override {
#ifdef _WIN32
        std::string cmd = "ctest --output-on-failure -C Debug";
        if (suite != "all") cmd += " -R " + suite;
        cmd += " 2>&1";
        return runProcessCapture(cmd, output);
#else
        std::string cmd = "ctest --output-on-failure";
        if (suite != "all") cmd += " -R " + suite;
        cmd += " 2>&1";
        return runProcessCapture(cmd, output);
#endif
    }

    bool executeShell(const std::string& command, bool powershell, std::string& output) override {
#ifdef _WIN32
        std::string cmd = powershell
            ? ("powershell -NoProfile -Command \"" + command + "\" 2>&1")
            : (command + " 2>&1");
        return runProcessCapture(cmd, output);
#else
        std::string cmd = command + " 2>&1";
        return runProcessCapture(cmd, output);
#endif
    }

    bool analyzeBinary(const std::string& path, std::string& output) override {
#ifdef _WIN32
        std::string cmd = "dumpbin /summary \"" + path + "\" 2>&1";
#else
        std::string cmd = "file \"" + path + "\" 2>&1";
#endif
        return runProcessCapture(cmd, output);
    }

    bool verifyCode(const std::string& path, std::string& output) override {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            output = "[Verify] File not found: " + path;
            return false;
        }
        std::ifstream f(path);
        if (!f.is_open()) {
            output = "[Verify] Cannot open: " + path;
            return false;
        }
        std::string line;
        int lineNo = 0;
        std::ostringstream os;
        os << "[Verify] " << path << " analysis:\n";
        int braceOpen = 0, braceClose = 0, parenOpen = 0, parenClose = 0;
        std::vector<std::string> issues;
        while (std::getline(f, line)) {
            ++lineNo;
            for (char c : line) {
                if (c == '{') ++braceOpen;
                else if (c == '}') ++braceClose;
                else if (c == '(') ++parenOpen;
                else if (c == ')') ++parenClose;
            }
        }
        if (braceOpen != braceClose)
            issues.push_back("Unbalanced braces: { = " + std::to_string(braceOpen) + " } = " + std::to_string(braceClose));
        if (parenOpen != parenClose)
            issues.push_back("Unbalanced parentheses: ( = " + std::to_string(parenOpen) + " ) = " + std::to_string(parenClose));
        if (issues.empty()) {
            os << "  OK - " << lineNo << " lines, braces balanced, parentheses balanced\n";
            output = os.str();
            return true;
        }
        for (const auto& i : issues) os << "  ISSUE: " << i << "\n";
        output = os.str();
        return false;
    }

    void setNativeCompilerAvailable(bool ok) { m_nativeCompilerOk = ok; }

private:
    bool m_nativeCompilerOk = true;

    static bool runProcessCapture(const std::string& cmd, std::string& output) {
#ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) { output = "[Process] failed to spawn"; return false; }
        std::ostringstream ss;
        char buf[4096];
        while (fgets(buf, sizeof(buf), pipe)) ss << buf;
        int rc =
#ifdef _WIN32
            _pclose(pipe);
#else
            pclose(pipe);
#endif
        output = ss.str();
        return rc == 0;
    }
};

// =============================================================================
// Deep2InferenceRouter
// =============================================================================
Deep2::GenerationOptions Deep2InferenceRouter::profileToOptions(const rawrxd::agentic::hexmag::GenProfile& profile) {
    Deep2::GenerationOptions opts;
    opts.maxTokens = 2048;
    opts.temperature = static_cast<float>(profile.tempMilli) / 1000.0f;
    if (opts.temperature <= 0.0f) opts.temperature = 0.2f;
    opts.topP = static_cast<float>(profile.topPMilli) / 1000.0f;
    if (opts.topP <= 0.0f) opts.topP = 0.95f;
    opts.topK = 40;
    opts.seed = static_cast<uint64_t>(profile.mutationNonce) * 2654435761ull + 0x9E3779B97F4A7C15ull;
    return opts;
}

std::string Deep2InferenceRouter::buildSpecialistPrompt(const std::string& userPrompt, const SpecialistConfig& specialist) {
    std::ostringstream os;
    os << "SYSTEM: You are a HexMag specialist agent.\n"
       << "Specialist: " << specialist.name << "\n"
       << "Role: " << (specialist.systemPrompt.empty() ? "Produce a verified, actionable engineering answer." : specialist.systemPrompt)
       << "\nConstraints:\n"
       << "  - Only state facts supported by supplied context or tool evidence.\n"
       << "  - Never simulate success. If something failed, say so.\n"
       << "  - Prefer concrete file paths, symbols, and commands.\n"
       << "Available tools for this specialist: ";
    for (size_t i = 0; i < specialist.allowedTools.size(); ++i) {
        os << specialist.allowedTools[i] << (i + 1 < specialist.allowedTools.size() ? ", " : "\n");
    }
    if (specialist.allowedTools.empty()) os << "(none)\n";
    os << "\nUSER TASK:\n" << userPrompt << "\nASSISTANT:";
    return os.str();
}

std::string Deep2InferenceRouter::generateForSpecialist(
    const std::string& prompt, const SpecialistConfig& specialist, const rawrxd::agentic::hexmag::GenProfile& profile) {
    if (!m_engine || !m_engine->isModelLoaded()) {
        return "[Deep2] ERROR: no native model loaded â€” cannot generate (offline mode requires a local model).";
    }
    const std::string full = buildSpecialistPrompt(prompt, specialist);
    const auto opts = profileToOptions(profile);
    return m_engine->generateText(full, opts.maxTokens);
}

void Deep2InferenceRouter::generateForSpecialistStream(
    const std::string& prompt, const SpecialistConfig& specialist,
    const rawrxd::agentic::hexmag::GenProfile& profile,
    std::function<void(const std::string& token)> onToken,
    std::function<void(const std::string& fullResponse)> onComplete,
    std::function<void(const std::string& error)> onError) {
    if (!m_engine || !m_engine->isModelLoaded()) {
        if (onError) onError("[Deep2] no native model loaded");
        return;
    }
    const std::string full = buildSpecialistPrompt(prompt, specialist);
    const auto opts = profileToOptions(profile);
    std::string accumulated;
    auto cb = [&](int32_t tokenId, const std::string& token) -> bool {
        accumulated += token;
        if (onToken) onToken(token);
        return true;
    };
    try {
        m_engine->generateStream(full, opts, cb);
    } catch (const std::exception& e) {
        if (onError) onError(e.what());
        return;
    }
    if (onComplete) onComplete(accumulated);
}

// =============================================================================
// SwarmContextManager
// =============================================================================
std::shared_ptr<SwarmContextManager::SharedContext> SwarmContextManager::createContext(const std::string& taskId, const std::string& request) {
    auto ctx = std::make_shared<SharedContext>();
    ctx->taskId = taskId;
    ctx->originalRequest = request;
    ctx->taskState = nlohmann::json::object();
    std::lock_guard<std::mutex> lk(m_contextsMutex);
    m_contexts[taskId] = ctx;
    return ctx;
}

std::shared_ptr<SwarmContextManager::SharedContext> SwarmContextManager::getContext(const std::string& taskId) {
    std::lock_guard<std::mutex> lk(m_contextsMutex);
    auto it = m_contexts.find(taskId);
    return it != m_contexts.end() ? it->second : nullptr;
}

void SwarmContextManager::removeContext(const std::string& taskId) {
    std::lock_guard<std::mutex> lk(m_contextsMutex);
    m_contexts.erase(taskId);
}

void SwarmContextManager::addAgentMessage(std::shared_ptr<SharedContext> ctx, const std::string& agentId, const std::string& message) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lk(ctx->mutex);
    ctx->agentMessages.push_back("[" + agentId + "] " + message);
}

void SwarmContextManager::addEvidence(std::shared_ptr<SharedContext> ctx, const std::string& evidence) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lk(ctx->mutex);
    ctx->evidence.push_back(evidence);
}

void SwarmContextManager::cacheFileContent(std::shared_ptr<SharedContext> ctx, const std::string& path, const std::string& content) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lk(ctx->mutex);
    ctx->fileContents[path] = content;
}

std::string SwarmContextManager::getCachedFileContent(std::shared_ptr<SharedContext> ctx, const std::string& path) {
    if (!ctx) return "";
    std::lock_guard<std::mutex> lk(ctx->mutex);
    auto it = ctx->fileContents.find(path);
    return it != ctx->fileContents.end() ? it->second : "";
}

nlohmann::json SwarmContextManager::getTaskState(std::shared_ptr<SharedContext> ctx) {
    if (!ctx) return nlohmann::json::object();
    std::lock_guard<std::mutex> lk(ctx->mutex);
    return ctx->taskState;
}

void SwarmContextManager::updateTaskState(std::shared_ptr<SharedContext> ctx, const nlohmann::json& state) {
    if (!ctx) return;
    std::lock_guard<std::mutex> lk(ctx->mutex);
    ctx->taskState = state;
}

// =============================================================================
// ConflictResolver
// =============================================================================
bool ConflictResolver::editsOverlap(const Edit& a, const Edit& b) {
    if (a.filePath != b.filePath) return false;
    return !(a.endLine < b.startLine || b.endLine < a.startLine);
}

std::vector<ConflictResolver::Conflict> ConflictResolver::detectConflicts(const std::vector<Edit>& edits) {
    // Delegates to the certified ConflictEngine (hexmag_resilience_bridge).
    // The certified detector adds semantic, dependency and logic-conflict
    // detection plus per-pair de-duplication on top of range overlap, and it
    // skips same-agent pairs, which the previous inline version did not.
    using RawrXD::HexMagResilience::toEngineEdit;

    std::vector<RawrXD::ConflictEngine::Edit> engineEdits;
    engineEdits.reserve(edits.size());
    for (const auto& e : edits) {
        int sl = static_cast<int>(e.startLine);
        int el = static_cast<int>(e.endLine);
        if (el < sl) el = sl;
        engineEdits.push_back(toEngineEdit(e.filePath, e.agentId, sl, el,
                                           e.oldContent, e.newContent));
    }

    RawrXD::ConflictEngine::ConflictDetector detector;
    auto engineConflicts = detector.detectConflicts(engineEdits);

    std::vector<Conflict> conflicts;
    conflicts.reserve(engineConflicts.size());
    for (const auto& ec : engineConflicts) {
        Conflict c;
        c.filePath = ec.filePath;
        c.conflictingEdits.reserve(ec.conflictingEdits.size());
        for (const auto& ee : ec.conflictingEdits) {
            Edit e;
            e.filePath   = ee.filePath;
            e.startLine  = ee.range.startLine;
            e.endLine    = ee.range.endLine;
            e.oldContent = ee.oldText;
            e.newContent = ee.newText;
            e.agentId    = ee.agentId;
            c.conflictingEdits.push_back(e);
        }
        // The engine classifies the conflict; surface that instead of the
        // blanket "manual" this function used to report for every case.
        switch (ec.type) {
            case RawrXD::ConflictEngine::Conflict::ConflictType::TextOverlap:      c.resolution = "overlap";    break;
            case RawrXD::ConflictEngine::Conflict::ConflictType::SemanticOverlap:  c.resolution = "semantic";   break;
            case RawrXD::ConflictEngine::Conflict::ConflictType::DependencyConflict:c.resolution = "dependency"; break;
            case RawrXD::ConflictEngine::Conflict::ConflictType::LogicConflict:    c.resolution = "logic";      break;
            default:                                                              c.resolution = "style";      break;
        }
        conflicts.push_back(c);
    }
    RawrXD::HexMagResilience::status().usedCertifiedConflictEngine = true;
    return conflicts;
}

std::string ConflictResolver::mergeEdits(const std::vector<Edit>& edits) {
    // Delegates to the certified ThreeWayMerge. The previous implementation
    // returned only edits.back().newContent, which discarded every other
    // participating edit. It now merges them and surfaces real conflicts.
    using RawrXD::HexMagResilience::toEngineEdit;

    std::vector<RawrXD::ConflictEngine::Edit> engineEdits;
    engineEdits.reserve(edits.size());
    for (const auto& e : edits) {
        int sl = static_cast<int>(e.startLine);
        int el = static_cast<int>(e.endLine);
        if (el < sl) el = sl;
        engineEdits.push_back(toEngineEdit(e.filePath, e.agentId, sl, el,
                                           e.oldContent, e.newContent));
    }

    auto results = RawrXD::HexMagResilience::resolveSwarmEdits("merge", engineEdits);
    std::ostringstream os;
    for (const auto& r : results) {
        os << r.mergedText;
        if (&r != &results.back()) os << "\n";
    }
    return os.str();
}

std::vector<ConflictResolver::Edit> ConflictResolver::resolveConflicts(const std::vector<Conflict>& conflicts, const std::string& strategy) {
    // Delegates to the certified ConflictResolver. An unrecognised strategy is
    // refused rather than silently coerced to a lossy default.
    if (!RawrXD::HexMagResilience::ensureConflictPolicy(strategy)) {
        return {};   // fail closed: caller sees no edits, not bogus ones
    }

    using RawrXD::HexMagResilience::toEngineEdit;
    std::vector<RawrXD::ConflictEngine::Edit> engineEdits;
    for (const auto& c : conflicts) {
        for (const auto& e : c.conflictingEdits) {
            int sl = static_cast<int>(e.startLine);
            int el = static_cast<int>(e.endLine);
            if (el < sl) el = sl;
            engineEdits.push_back(toEngineEdit(e.filePath, e.agentId, sl, el,
                                               e.oldContent, e.newContent));
        }
    }

    auto results = RawrXD::HexMagResilience::resolveSwarmEdits(strategy, engineEdits);

    std::vector<Edit> resolved;
    for (const auto& r : results) {
        Edit merged;
        merged.filePath   = r.filePath;
        merged.agentId    = "certified_conflict_engine";
        merged.startLine  = 0;
        merged.endLine    = 0;
        merged.oldContent = "";
        merged.newContent = r.mergedText;
        resolved.push_back(merged);
    }
    RawrXD::HexMagResilience::status().usedCertifiedConflictEngine = true;
    return resolved;
}

bool ConflictResolver::threeWayMerge(const std::string& base, const std::string& ours, const std::string& theirs, std::string& merged) {
    // Delegates to the certified ThreeWayMerge engine, preserving the original
    // contract: true when the merge completed cleanly, false when it produced
    // conflict markers.
    RawrXD::ConflictEngine::ThreeWayMerge merger;
    auto mr = merger.merge(base, ours, theirs);

    merged = mr.mergedText;
    return mr.conflictCount == 0;
}

// =============================================================================
// HexMagSwarmOrchestrator
// =============================================================================
HexMagSwarmOrchestrator::HexMagSwarmOrchestrator() = default;
HexMagSwarmOrchestrator::~HexMagSwarmOrchestrator() { shutdown(); }

bool HexMagSwarmOrchestrator::initialize(const std::string& workingDir) {
    if (m_initialized.load()) return true;
    m_workingDir = workingDir.empty() ? std::string(".") : workingDir;

    // SubAgentManager requires an AgenticEngine â€” the swarm's engine pointer is
    // null at this layer; SubAgentManager tolerates it (it checks m_engine != null).
    m_subAgentManager = std::make_unique<SubAgentManager>(nullptr);

    // AgentOrchestrator (agentic loop + advanced coordinator)
    m_agentOrchestrator = std::make_unique<Agent::AgentOrchestrator>();
    m_agentOrchestrator->SetConfig(Agent::OrchestratorConfig{
        15, 32000, true, true, false, true, m_workingDir});

      // Enable advanced coordination (load balancing, health, scaling, fault tol)
      m_agentOrchestrator->EnableAdvancedCoordination(Agentic::ScalingPolicy{}, Agentic::RedundancyConfig{});
      // instance() returns a reference to a process-wide singleton owned by
      // AdvancedAgentCoordinator itself. A unique_ptr previously tried to take
      // ownership via operator=(raw*) (which does not exist) and would have been
      // wrong anyway, so this is a non-owning observer pointer.
      m_advancedCoordinator = &Agentic::AdvancedAgentCoordinator::instance();

    // CEOAgent (autonomous engineering controller)
    m_ceoAgent = std::make_unique<Agents::CEOAgent>();
    m_ceoAgent->Initialize(m_deep2Engine, nullptr, nullptr);

    // Shared context + conflict resolution
    m_contextManager = std::make_unique<SwarmContextManager>();
    m_conflictResolver = std::make_unique<ConflictResolver>();

    // Native tool executor (real operations)
    auto executor = std::make_unique<RealNativeToolExecutor>();
    m_nativeToolExecutor = executor.get();
    m_ownedNativeExecutor = std::move(executor);

    // Default specialists (10 HexMag specialists)
    registerSpecialist({"planner", Agentic::Specialist::HX_SPEC_PLANNER,
        "Decompose the task into ordered, verifiable subtasks with dependencies.",
        {"grep_files","search_files","read_file","list_dir"}, 0.1, 0.9, 2048, 3});
    registerSpecialist({"falsifier", Agentic::Specialist::HX_SPEC_FALSIFIER,
        "Try to falsify the current approach; find boundary cases and contradictions.",
        {"grep_files","read_file","run_build","run_tests"}, 0.3, 0.95, 2048, 3});
    registerSpecialist({"boundary", Agentic::Specialist::HX_SPEC_BOUNDARY,
        "Check boundary conditions, empty inputs, overflow, and edge cases.",
        {"read_file","run_tests"}, 0.2, 0.95, 2048, 3});
    registerSpecialist({"consistency", Agentic::Specialist::HX_SPEC_CONSISTENCY,
        "Verify the change is consistent with the rest of the codebase.",
        {"grep_files","search_files","reference_symbol"}, 0.2, 0.9, 2048, 3});
    registerSpecialist({"resolver", Agentic::Specialist::HX_SPEC_RESOLVER,
        "Produce the concrete, verifiable fix (patch, build, test).",
        {"read_file","write_file","replace_in_file","run_build","run_tests","shell"}, 0.2, 0.95, 4096, 3});
    registerSpecialist({"assumption_breaker", Agentic::Specialist::HX_SPEC_ASSUMPTION_BREAKER,
        "Challenge assumptions in the task statement and in prior agent output.",
        {"grep_files","read_file"}, 0.4, 0.95, 2048, 3});
    registerSpecialist({"test_driven", Agentic::Specialist::HX_SPEC_TEST_DRIVEN,
        "Write or run tests that prove the fix; run the failing test first.",
        {"read_file","write_file","run_tests","run_build"}, 0.2, 0.9, 4096, 3});
    registerSpecialist({"alt_derivation", Agentic::Specialist::HX_SPEC_ALT_DERIVATION,
        "Produce an independent second derivation or fix strategy.",
        {"read_file","write_file","run_build"}, 0.4, 0.95, 2048, 3});
    registerSpecialist({"epistemic", Agentic::Specialist::HX_SPEC_EPISTEMIC,
        "State only what is provable from supplied evidence; mark unverified claims.",
        {"read_file","grep_files"}, 0.1, 0.9, 2048, 3});
    registerSpecialist({"generalist", Agentic::Specialist::HX_SPEC_GENERALIST,
        "Broad engineering analysis; coordinate specialists and summarize.",
        {"grep_files","read_file","list_dir"}, 0.3, 0.95, 2048, 3});

    m_initialized.store(true);
    return true;
}

void HexMagSwarmOrchestrator::shutdown() {
    if (!m_initialized.load()) return;
    m_running.store(false);
    if (m_subAgentManager) m_subAgentManager->cancelAll();
    if (m_agentOrchestrator) {
        m_agentOrchestrator->Cancel();
    }
    m_initialized.store(false);
}

void HexMagSwarmOrchestrator::registerSpecialist(const SpecialistConfig& config) {
    std::lock_guard<std::mutex> lk(m_specialistMutex);
    m_specialists[config.specialistType] = config;
}

std::vector<SpecialistConfig> HexMagSwarmOrchestrator::getSpecialists() const {
    std::lock_guard<std::mutex> lk(m_specialistMutex);
    std::vector<SpecialistConfig> out;
    for (const auto& [_, cfg] : m_specialists) out.push_back(cfg);
    return out;
}

SpecialistConfig HexMagSwarmOrchestrator::getDefaultSpecialist(RawrXD::Agentic::Specialist type) const {
    std::lock_guard<std::mutex> lk(m_specialistMutex);
    auto it = m_specialists.find(type);
    return it != m_specialists.end() ? it->second : SpecialistConfig{};
}

void HexMagSwarmOrchestrator::setDeep2Engine(Deep2::Deep2Engine* engine) {
    m_deep2Engine = engine;
}

Deep2::Deep2Engine* HexMagSwarmOrchestrator::getDeep2Engine() const { return m_deep2Engine; }

void HexMagSwarmOrchestrator::setNativeToolExecutor(NativeToolExecutor* executor) {
    m_nativeToolExecutor = executor;
}

NativeToolExecutor* HexMagSwarmOrchestrator::getNativeToolExecutor() const { return m_nativeToolExecutor; }

void HexMagSwarmOrchestrator::setIDEReporter(IDEReporter* reporter) {
    m_ideReporter = reporter;
}

void HexMagSwarmOrchestrator::reportProgress(const std::string& stage, float percent, const std::string& detail) {
    if (m_progressCallback) m_progressCallback(stage, percent, detail);
    if (m_ideReporter) m_ideReporter->onTaskProgress("swarm_task", stage, percent, detail);
}

void HexMagSwarmOrchestrator::reportToolActivity(const std::string& agentId, const std::string& tool, const std::string& status) {
    if (m_toolActivityCallback) m_toolActivityCallback(agentId, tool, status);
    if (m_ideReporter) m_ideReporter->onToolResult(agentId, tool, status.find("OK") != std::string::npos, status);
}

// ---- Pipeline: Planning ----
TaskDecomposition HexMagSwarmOrchestrator::decomposeTask(const std::string& userRequest) {
    TaskDecomposition decomp;
    decomp.originalTask = userRequest;

    // Structural planning: differentiate analysis vs fix vs verify phases.
    // Parallelizable stages run concurrently; verification gates depend on the fix.
    const bool looksLikeDebug = [&] {
        std::string low = userRequest;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        return low.find("fail") != std::string::npos || low.find("test") != std::string::npos ||
               low.find("bug") != std::string::npos || low.find("error") != std::string::npos ||
               low.find("fix") != std::string::npos;
    }();

    decomp.subtasks = {
        "Analyze the task and scope: " + userRequest,
        "Locate relevant source files and symbols for: " + userRequest,
        "Diagnose root cause and required change for: " + userRequest,
        "Implement the fix for: " + userRequest,
        "Build the affected target with the native toolchain.",
        "Run the failing test to verify the fix.",
        "Independently review the change and report findings."
    };
    decomp.assignedSpecialists = {
        Agentic::Specialist::HX_SPEC_PLANNER,
        Agentic::Specialist::HX_SPEC_GENERALIST,
        Agentic::Specialist::HX_SPEC_FALSIFIER,
        Agentic::Specialist::HX_SPEC_RESOLVER,
        Agentic::Specialist::HX_SPEC_TEST_DRIVEN,
        Agentic::Specialist::HX_SPEC_TEST_DRIVEN,
        Agentic::Specialist::HX_SPEC_CONSISTENCY
    };
    decomp.requiredTools = {"grep_files","search_files","reference_symbol","read_file","write_file","replace_in_file","run_build","run_tests"};
    decomp.priority = looksLikeDebug ? Agentic::TaskPriority::HIGH : Agentic::TaskPriority::NORMAL;
    decomp.dependencies = {
        {2, 1},  // diagnose depends on locate
        {3, 2},  // implement depends on diagnose
        {4, 3},  // build depends on implement
        {5, 3},  // test depends on implement
        {6, 3}   // review depends on implement
    };
    return decomp;
}

std::vector<std::string> HexMagSwarmOrchestrator::createSpecialistPrompts(const TaskDecomposition& decomp) {
    std::vector<std::string> prompts;
    for (size_t i = 0; i < decomp.subtasks.size(); ++i) {
        auto spec = getDefaultSpecialist(decomp.assignedSpecialists[i % decomp.assignedSpecialists.size()]);
        std::ostringstream os;
        os << "Specialist: " << spec.name << "\n"
           << "Role: " << spec.systemPrompt << "\n"
           << "Task: " << decomp.subtasks[i] << "\n"
           << "Allowed tools: ";
        if (spec.allowedTools.empty()) os << "(none)\n";
        else for (size_t k = 0; k < spec.allowedTools.size(); ++k)
            os << spec.allowedTools[k] << (k + 1 < spec.allowedTools.size() ? ", " : "\n");
        os << "Produce only evidence-supported output. Emit tool calls as TOOL:<name>:{\"arg\":\"value\"}.\n";
        prompts.push_back(os.str());
    }
    return prompts;
}

std::string HexMagSwarmOrchestrator::routeToDeep2(
    const std::string& prompt, const SpecialistConfig& specialist, const rawrxd::agentic::hexmag::GenProfile& profile) {
    Deep2InferenceRouter router(m_deep2Engine);
    return router.generateForSpecialist(prompt, specialist, profile);
}

// ---------------------------------------------------------------------------
// Maps a specialist onto the capability set its delegated agent must hold.
//
// RawrXD::Agentic::Specialist is an alias for the PLAIN (unscoped)
// rawrxd::agentic::hexmag::Specialist, whose members are HX_SPEC_*, so there
// are no scoped names such as Specialist::Builder.
//
// The DelegationManager refuses a task when an agent lacks a required
// capability, so this is the single place deciding what each kind of
// specialist is actually permitted to do.
// ---------------------------------------------------------------------------
std::vector<RawrXD::Delegation::AgentCapability>
HexMagSwarmOrchestrator::delegationCapabilities(const SpecialistConfig& spec) {
    using RawrXD::Delegation::AgentCapability;
    using RawrXD::Agentic::Specialist;

    std::vector<AgentCapability> caps;
    caps.push_back(AgentCapability::Research);   // every specialist may read/reason

    switch (spec.specialistType) {
        case Specialist::HX_SPEC_PLANNER:
            caps.push_back(AgentCapability::Planning);
            break;
        case Specialist::HX_SPEC_FALSIFIER:
        case Specialist::HX_SPEC_BOUNDARY:
        case Specialist::HX_SPEC_CONSISTENCY:
        case Specialist::HX_SPEC_ASSUMPTION_BREAKER:
            caps.push_back(AgentCapability::Verification);
            break;
        case Specialist::HX_SPEC_RESOLVER:
            caps.push_back(AgentCapability::Verification);
            caps.push_back(AgentCapability::Planning);   // resolves conflicts, may re-plan
            break;
        case Specialist::HX_SPEC_TEST_DRIVEN:
            caps.push_back(AgentCapability::BuildAndTest);
            caps.push_back(AgentCapability::Verification);
            break;
        case Specialist::HX_SPEC_ALT_DERIVATION:
            caps.push_back(AgentCapability::Research);
            break;
        case Specialist::HX_SPEC_GENERALIST:
        case Specialist::HX_SPEC_EPISTEMIC:
        default:
            break;   // research-only, which is already granted above
    }

    // Whatever tools the specialist was registered with decide write access.
    for (const auto& tool : spec.allowedTools) {
        if (tool == "edit" || tool == "write" || tool == "file_edit" || tool == "patch") {
            caps.push_back(AgentCapability::CodeEdit);
        } else if (tool == "git" || tool == "commit") {
            caps.push_back(AgentCapability::Git);
        }
    }
    return caps;
}

std::string HexMagSwarmOrchestrator::executeWithRepeatTuner(const std::string& task, const SpecialistConfig& specialist) {
    const std::uint64_t requestIdHash = rawrxd::agentic::hexmag::requestHash(task);
    std::string lastOutput;
    std::uint32_t failMask = 0;

    // ---------------------------------------------------------------------
    // Bounded retry via the CERTIFIED AdaptiveRetryEngine, replacing the old
    // bare attempt counter.
    //
    // The previous loop retried immediately with no backoff, no jitter, no
    // retryable/non-retryable classification and no circuit breaker, so a
    // permanently failing specialist burned every attempt as fast as it could
    // and a configuration fault was retried as if it were transient.
    //
    // Each attempt is expensive (model inference plus build and test), so back
    // off generously and allow few tries.
    // ---------------------------------------------------------------------
    static const std::string kSpecialistOp = "hexmag_specialist";

    RetryPolicy hexmagRetry;
    hexmagRetry.operationType = kSpecialistOp;
    hexmagRetry.description = "HexMag specialist attempt: model inference, build, and test";
    hexmagRetry.maxAttempts = 6;
    hexmagRetry.baseDelayMs = 2000;
    hexmagRetry.maxDelayMs = 30000;
    hexmagRetry.backoffMultiplier = 2.0;
    hexmagRetry.jitterFactor = 0.2;
    hexmagRetry.enableCircuitBreaker = true;
    hexmagRetry.failureThreshold = 3;
    hexmagRetry.successThreshold = 2;
    hexmagRetry.circuitTimeoutMs = 120000;
    hexmagRetry.retryableErrorPatterns = {"empty output", "build failed", "tests failed", "timeout", "temporary"};
    hexmagRetry.nonRetryableErrorPatterns = {"no native model loaded", "RepeatSession init failed",
                                             "specialist reported ERROR"};
    getGlobalRetryEngine().registerPolicy(hexmagRetry);

    const int maxAttempts = hexmagRetry.maxAttempts;
    int attemptsMade = 0;

    // One attempt returns either a terminal answer (success) or throws a
    // classified failure. The engine decides whether another try is warranted.
    auto runAttempt = [&]() -> std::string {
        const int attempt = attemptsMade + 1;
        rawrxd::agentic::hexmag::RepeatSession session(requestIdHash, static_cast<std::uint32_t>(maxAttempts));
        if (!session.valid()) {
            lastOutput = "[HexMag] RepeatSession init failed";
            failMask |= rawrxd::agentic::hexmag::HX_FAIL_UNSUPPORTED;
            throw std::runtime_error("RepeatSession init failed");
        }
        const auto directive = session.directive();
        const std::string prompt = task + "\n\n" + directive;

        std::string output;
        if (m_deep2Engine && m_deep2Engine->isModelLoaded()) {
            output = routeToDeep2(prompt, specialist, session.profile());
        } else {
            output = "[HexMag] no native model loaded; promot-level planning only";
        }

        if (output.empty()) {
            failMask |= rawrxd::agentic::hexmag::HX_FAIL_STAGNATION;
            throw std::runtime_error("empty output");
        }
        if (output.find("[ERROR]") != std::string::npos) {
            failMask |= rawrxd::agentic::hexmag::HX_FAIL_UNSUPPORTED;
            throw std::runtime_error("specialist reported ERROR");
        }

        lastOutput = output;

        if (m_enableAutoBuild) {
            std::string buildOut;
            if (!executeBuild("RawrXD", "Debug", buildOut)) {
                failMask |= rawrxd::agentic::hexmag::HX_FAIL_TEST;
                throw std::runtime_error("build failed: " + buildOut);
            }
            std::string testOut;
            if (!executeTests("test_generation", testOut)) {
                failMask |= rawrxd::agentic::hexmag::HX_FAIL_TEST;
                throw std::runtime_error("tests failed: " + testOut);
            }
            return "[HexMag] verified: model + build + test green\n" + output;
        }
        return output;
    };

    RetryResult outcome = getGlobalRetryEngine().execute(kSpecialistOp, runAttempt);

    // Count the attempts actually performed (runAttempt throws before the
    // engine increments its own counters, so track it locally).
    attemptsMade = outcome.attemptErrors.empty() && outcome.success
        ? outcome.attemptsMade
        : static_cast<int>(outcome.attemptErrors.size());

    if (outcome.success) {
        return outcome.result;
    }

    if (outcome.circuitBreakerTriggered) {
        return "[HexMag] circuit breaker OPEN after " + std::to_string(hexmagRetry.failureThreshold) +
               " verified failures; refusing to retry a persistently failing task. "
               "Last output follows (failure mask=0x" + std::to_string(failMask) + "):\n" + lastOutput;
    }

    if (!outcome.attemptErrors.empty()) {
        const std::string& lastError = outcome.attemptErrors.back();
        if (!isRetryableUnderPolicy(kSpecialistOp, lastError)) {
            return "[HexMag] stopped after 1 attempt (non-retryable fault). Last error: " +
                   lastError + "\nLast output follows (failure mask=0x" +
                   std::to_string(failMask) + "):\n" + lastOutput;
        }
    }

    return "[HexMag] exhausted " + std::to_string(attemptsMade) +
           " attempts (with backoff); still failing. Last error: " + outcome.errorMessage +
           "\nLast output follows (failure mask=0x" + std::to_string(failMask) + "):\n" + lastOutput;
}

SwarmExecutionResult HexMagSwarmOrchestrator::executeSwarmTask(
    const std::string& userRequest, ProgressCallback onProgress, ToolActivityCallback onToolActivity) {
    m_running.store(true);
    m_totalTasks.fetch_add(1);
    const auto t0 = std::chrono::high_resolution_clock::now();
    m_progressCallback = onProgress;
    m_toolActivityCallback = onToolActivity;

    SwarmExecutionResult result;
    const std::string taskId = "task_" + std::to_string(m_totalTasks.load());
    auto ctx = m_contextManager->createContext(taskId, userRequest);

    reportProgress("Planning", 0.0f, "Decomposing user request");
    TaskDecomposition decomp = decomposeTask(userRequest);

    // Wire dependencies into AdvancedAgentCoordinator
    if (m_advancedCoordinator) {
        for (size_t i = 0; i < decomp.subtasks.size(); ++i) {
            std::vector<std::string> prereqs;
            for (const auto& [task, dep] : decomp.dependencies) {
                if ((size_t)task == i) prereqs.push_back("subtask_" + std::to_string(dep));
            }
            m_advancedCoordinator->addTaskDependency("subtask_" + std::to_string(i), prereqs);
        }
    }

    reportProgress("Planning", 0.1f, "Created " + std::to_string(decomp.subtasks.size()) + " specialist subtasks");
    auto prompts = createSpecialistPrompts(decomp);

    result = executeParallelAgents(prompts, decomp);
    result = verifyAndMergeResults(result, decomp);

    m_totalLatencyMs.store(std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - t0).count());
    if (result.success) m_successfulTasks.fetch_add(1); else m_failedTasks.fetch_add(1);

    reportProgress("Complete", 1.0f, result.success ? "Swarm task succeeded" : "Swarm task failed");
    m_contextManager->removeContext(taskId);
    m_running.store(false);
    return result;
}

std::future<SwarmExecutionResult> HexMagSwarmOrchestrator::executeSwarmTaskAsync(
    const std::string& userRequest, ProgressCallback onProgress, ToolActivityCallback onToolActivity, CompletionCallback onComplete) {
    return std::async(std::launch::async, [this, userRequest, onProgress, onToolActivity, onComplete]() {
        auto res = executeSwarmTask(userRequest, onProgress, onToolActivity);
        if (onComplete) onComplete(res);
        return res;
    });
}

SwarmExecutionResult HexMagSwarmOrchestrator::executeParallelAgents(
    const std::vector<std::string>& prompts, const TaskDecomposition& decomp) {
    SwarmExecutionResult result;

    // Dependency-aware scheduling: only launch subtasks whose prerequisites are complete.
    std::unordered_map<size_t, std::vector<size_t>> prereqs;
    for (const auto& [task, dep] : decomp.dependencies) prereqs[(size_t)task].push_back((size_t)dep);

    std::unordered_map<size_t, std::future<std::string>> futures;
    std::unordered_map<size_t, bool> complete;

       size_t launched = 0;

       // -----------------------------------------------------------------
       // Delegated agent registration (CERTIFIED DelegationManager).
       //
       // The previous implementation launched subtasks with unbounded
       // std::async - no resource quotas, no depth cap, and no cooperative
       // cancellation, so a large decomposition could spawn every subtask at
       // once with no regard for token/time budget.
       //
       // Each subtask is now registered as a delegated agent with explicit
       // capability and quota enforcement. Because spawn decisions are made
       // here rather than by the manager's own scheduler, the manager is used
       // for its authoritative ACCOUNTING (quotas, depth, lifecycle) while
       // scheduling stays dependency-aware in this loop.
       // -----------------------------------------------------------------
       static const std::string kDelegationLabel = "HexMagSwarm";
       if (!m_delegationManager) {
           Delegation::DelegationManager::Config dcfg;
           dcfg.maxConcurrentAgents = kDelegationConcurrency;
           dcfg.maxDelegationDepth = kDelegationMaxDepth;
           dcfg.enforceQuotas = true;
           dcfg.autoStart = false;      // this loop owns execution
           m_delegationManager = std::make_unique<Delegation::DelegationManager>(dcfg);
           m_delegationManager->setAgentWorkFn(
               [](Delegation::DelegatedAgent&, const Delegation::DelegatedTask&) -> std::string {
                   // Real work happens in std::async below; the manager tracks
                   // lifecycle and quotas only. Returning success here would be
                   // a fabricated result, so this must never run.
                   throw std::runtime_error(
                       "delegation work function invoked without an executor wired");
               });
       }

       auto launch = [&](size_t idx) {
           const auto spec = getDefaultSpecialist(decomp.assignedSpecialists[idx % decomp.assignedSpecialists.size()]);
           result.agentsSpawned++;

           // Every subtask gets an explicit quota, so a runaway subtask cannot
           // consume the whole swarm's budget.
           Delegation::ResourceLimits limits;
           limits.maxTokens = 200000;      // generous: specialists reason in-context
           limits.maxWallTimeMs = 300000;
           limits.maxCpuTimeMs = 120000;
           limits.maxToolCalls = 100;
           limits.maxFileEdits = 25;
           limits.maxSubProcesses = 4;
           limits.maxSubAgents = 2;

           const std::string agentId = m_delegationManager->createAgent(
               "specialist_" + std::to_string(idx), delegationCapabilities(spec), limits);
           if (agentId.empty()) {
               result.errors.push_back("subtask " + std::to_string(idx) +
                                       " rejected by delegation quota/depth policy");
               complete[idx] = false;
               return;
           }

           futures[idx] = std::async(std::launch::async, [this, idx, prompt = prompts[idx], spec]() -> std::string {
               reportToolActivity("agent_" + std::to_string(idx), "specialist_init", "OK " + spec.name);
               std::string out = executeWithRepeatTuner(prompt, spec);
            if (out.find("[ERROR]") == 0 && out.find("[HexMag] verified") == std::string::npos) {
                // parse hex mag tool calls from the model output
                std::string toolResult;
                std::string realOut = m_subAgentManager
                    ? m_subAgentManager->dispatchToolCall("agent_" + std::to_string(idx), out, toolResult)
                        ? (out + "\n[tool]\n" + toolResult) : out
                    : out;
                out = realOut;
            }
            return out;
        });
        launched++;
    };

    // Schedule loop with a bounded parallel limit
    while (complete.size() < prompts.size()) {
        for (size_t i = 0; i < prompts.size(); ++i) {
            if (complete.count(i) || futures.count(i)) continue;
            bool ready = true;
            if (prereqs.count(i)) {
                for (size_t p : prereqs[i]) {
                    if (!complete.count(p)) { ready = false; break; }
                    else if (!complete[p]) { result.errors.push_back("subtask " + std::to_string(i) + " blocked by prereq " + std::to_string(p)); ready = false; break; }
                }
            }
            if (!ready) continue;
            if (launched - complete.size() >= (size_t)m_maxParallelAgents) continue;
            launch(i);
        }

        // Collect any completed
        for (auto& [idx, fut] : futures) {
            if (complete.count(idx)) continue;
            if (fut.wait_for(std::chrono::seconds(0)) != std::future_status::ready) continue;
            std::string res = fut.get();
            result.agentResults.push_back(res);
            complete[idx] = res.find("[ERROR]") == std::string::npos && res.find("failed") == std::string::npos;
            result.agentsCompleted++;
            if (!complete[idx]) {
                result.agentsFailed++;
                result.errors.push_back("subtask " + std::to_string(idx) + " failed");
            }
        }
        if (complete.size() == futures.size() && launched == complete.size()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Join
    for (auto& [idx, fut] : futures) if (fut.valid()) fut.wait();

    // Merge
    std::ostringstream merged;
    for (const auto& r : result.agentResults) merged << r << "\n---\n";
    result.mergedOutput = merged.str();
    result.evidence["agents"] = result.agentResults.size();
    result.evidence["errors"] = result.errors;
    return result;
}

SwarmExecutionResult HexMagSwarmOrchestrator::verifyAndMergeResults(const SwarmExecutionResult& raw, const TaskDecomposition& decomp) {
    SwarmExecutionResult result = raw;

    // Conflict detection across file-modifying specialists
    if (m_enableConflictResolution) {
        std::vector<ConflictResolver::Edit> edits;
        for (const auto& r : raw.agentResults) {
            std::regex editRe(R"((?:\[agent:\s*([\w_-]+)\]\s*)?(?:WRITE_FILE|EDIT_FILE)\s+([^\s]+))");
            std::smatch m;
            std::string::const_iterator s = r.begin();
            while (std::regex_search(s, r.end(), m, editRe)) {
                ConflictResolver::Edit e;
                e.filePath = m[2];
                e.agentId = m[1].matched ? m[1].str() : "unknown";
                e.startLine = e.endLine = 0;
                edits.push_back(e);
                s = m.suffix().first;
            }
        }
        auto conflicts = m_conflictResolver->detectConflicts(edits);
        result.evidence["conflicts_detected"] = conflicts.size();
        if (!conflicts.empty()) {
            result.errors.push_back("Detected " + std::to_string(conflicts.size()) + " edit conflicts");
            m_conflictResolver->resolveConflicts(conflicts, "merge");
        }
    }

    // Final verification cycle: build + test with the native toolchain
    bool verified = false;
    if (m_enableAutoBuild || m_enableAutoTest) {
        verified = runVerificationCycle(result, decomp);
    } else {
        verified = raw.agentsFailed == 0;
    }

    result.success = verified && raw.agentsCompleted > 0;
    result.evidence["verified"] = result.success;
    result.evidence["agents_completed"] = raw.agentsCompleted;
    result.evidence["agents_failed"] = raw.agentsFailed;
    return result;
}

bool HexMagSwarmOrchestrator::runVerificationCycle(SwarmExecutionResult& result, const TaskDecomposition& decomp) {
    (void)decomp;
    bool ok = true;
    if (m_enableAutoBuild) {
        std::string out;
        bool buildOk = m_nativeToolExecutor ? m_nativeToolExecutor->runBuild("RawrXD", "Debug", out) : false;
        result.buildResults.push_back(out);
        result.evidence["build"] = buildOk;
        if (!buildOk) ok = false;
    }
    if (m_enableAutoTest) {
        std::string out;
        bool testOk = m_nativeToolExecutor ? m_nativeToolExecutor->runTests("test_generation", out) : false;
        result.testResults.push_back(out);
        result.evidence["test"] = testOk;
        if (!testOk) ok = false;
    }
    return ok;
}

bool HexMagSwarmOrchestrator::executeNativeTool(const std::string& toolName, const nlohmann::json& args, std::string& output) {
    if (!m_nativeToolExecutor) {
        output = "[HexMag] NativeToolExecutor not installed";
        return false;
    }
    auto extract = [&](const char* key) -> std::string {
        return args.contains(key) && args[key].is_string() ? args[key].get<std::string>() : std::string{};
    };
    bool ok = false;
    if (toolName == "read_file") {
        ok = m_nativeToolExecutor->readFile(extract("path"), output);
    } else if (toolName == "write_file") {
        ok = m_nativeToolExecutor->writeFile(extract("path"), extract("content"));
        output = "[write_file] " + extract("path") + (ok ? " OK" : " FAILED");
    } else if (toolName == "list_dir") {
        std::vector<std::string> e;
        ok = m_nativeToolExecutor->listDir(extract("path"), e);
        std::ostringstream os; for (auto& x : e) os << x << "\n"; output = os.str();
    } else if (toolName == "grep_files") {
        ok = m_nativeToolExecutor->grepFiles(extract("pattern"), extract("path"), output);
    } else if (toolName == "search_files") {
        ok = m_nativeToolExecutor->searchFiles(extract("query"), extract("path"), output);
    } else if (toolName == "reference_symbol") {
        ok = m_nativeToolExecutor->referenceSymbol(extract("symbol"), output);
    } else if (toolName == "run_build") {
        ok = m_nativeToolExecutor->runBuild(extract("target"), extract("config"), output);
    } else if (toolName == "run_tests") {
        ok = m_nativeToolExecutor->runTests(extract("suite"), output);
    } else if (toolName == "shell" || toolName == "run_in_terminal") {
        ok = m_nativeToolExecutor->executeShell(extract("cmd"), false, output);
    } else if (toolName == "powershell") {
        ok = m_nativeToolExecutor->executeShell(extract("cmd"), true, output);
    } else if (toolName == "analyze_binary") {
        ok = m_nativeToolExecutor->analyzeBinary(extract("path"), output);
    } else if (toolName == "verify_code") {
        ok = m_nativeToolExecutor->verifyCode(extract("path"), output);
    } else {
        output = "[HexMag] unknown tool: " + toolName;
    }
    if (m_ideReporter) {
        m_ideReporter->onToolResult("swarm", toolName, ok, output.substr(0, 256));
    }
    return ok;
}

bool HexMagSwarmOrchestrator::executeBuild(const std::string& target, const std::string& config, std::string& output) {
    return m_nativeToolExecutor ? m_nativeToolExecutor->runBuild(target, config, output) : false;
}

bool HexMagSwarmOrchestrator::executeTests(const std::string& suite, std::string& output) {
    return m_nativeToolExecutor ? m_nativeToolExecutor->runTests(suite, output) : false;
}

bool HexMagSwarmOrchestrator::executeShell(const std::string& command, bool powershell, std::string& output) {
    return m_nativeToolExecutor ? m_nativeToolExecutor->executeShell(command, powershell, output) : false;
}

bool HexMagSwarmOrchestrator::detectConflicts(const std::vector<std::string>& edits) {
    std::vector<ConflictResolver::Edit> parsed;
    for (const auto& e : edits) {
        ConflictResolver::Edit edit;
        size_t p = e.find(':');
        edit.filePath = p == std::string::npos ? e : e.substr(0, p);
        parsed.push_back(edit);
    }
    return !m_conflictResolver->detectConflicts(parsed).empty();
}

bool HexMagSwarmOrchestrator::resolveConflicts(std::vector<std::string>& edits) {
    std::vector<ConflictResolver::Edit> parsed;
    for (const auto& e : edits) {
        ConflictResolver::Edit edit; edit.filePath = e; parsed.push_back(edit);
    }
    auto conflicts = m_conflictResolver->detectConflicts(parsed);
    if (conflicts.empty()) return true;
    auto resolved = m_conflictResolver->resolveConflicts(conflicts, "merge");
    edits.clear();
    for (const auto& r : resolved) edits.push_back(r.filePath + ":" + r.newContent);
    return true;
}

void HexMagSwarmOrchestrator::collectEvidence(SwarmExecutionResult& result, const std::string& agentId,
                                              const std::string& tool, const std::string& output, bool success) {
    result.toolExecutions.push_back("[" + agentId + "] " + tool + (success ? " OK" : " FAILED"));
    std::ostringstream os;
    os << "[" << agentId << "] " << tool << (success ? " OK" : " FAILED") << "\n" << output.substr(0, 4096);
    result.evidence["tool_log"] = result.evidence.value("tool_log", std::vector<std::string>{});
    result.evidence["tool_log"].push_back(os.str());
}

std::string HexMagSwarmOrchestrator::getStatusSummary() const {
    std::ostringstream os;
    os << "HexMagSwarm: initialized=" << m_initialized.load()
       << " running=" << m_running.load()
       << " tasks=" << m_totalTasks.load()
       << " ok=" << m_successfulTasks.load()
       << " fail=" << m_failedTasks.load()
       << " deep2=" << (m_deep2Engine && m_deep2Engine->isModelLoaded() ? 1 : 0);
    return os.str();
}

nlohmann::json HexMagSwarmOrchestrator::getMetrics() const {
    return {
        {"tasks", m_totalTasks.load()},
        {"successful", m_successfulTasks.load()},
        {"failed", m_failedTasks.load()},
        {"total_latency_ms", m_totalLatencyMs.load()},
        {"initialized", m_initialized.load()},
        {"deep2_model", (m_deep2Engine && m_deep2Engine->isModelLoaded())}
    };
}

} // namespace HexMag
} // namespace RawrXD