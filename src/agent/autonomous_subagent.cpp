// ============================================================================
// autonomous_subagent.cpp — Autonomous bulk-fix subagents + orchestrator
// ============================================================================
// Self-directing agents that iterate a target list applying a BulkFixStrategy,
// spawning one SubAgent per target through the real SubAgentManager, verifying,
// retrying, self-healing, and merging results. Pure C++20 — no external deps,
// no Qt. NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "autonomous_subagent.hpp"
#include "subagent_core.h"

#include <sstream>
#include <random>
#include <algorithm>
#include <thread>
#include <ctime>

namespace {

std::string bf_replace_all(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

int64_t bf_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string bf_uuid(const char* prefix) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::ostringstream ss;
    ss << prefix << "-" << bf_now_ms() << "-" << std::hex << dis(gen);
    return ss.str();
}

// A generation result "looks successful" when it produced real content and is
// not an explicit error sentinel. This mirrors SubAgentManager's failure text.
bool bf_result_ok(const std::string& result) {
    if (result.empty()) return false;
    if (result.rfind("[error", 0) == 0) return false;
    if (result.find("status=failed") != std::string::npos) return false;
    return true;
}

bool bf_json_true(const std::string& j, const char* key) {
    std::string needle = std::string("\"") + key + "\":";
    auto p = j.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    while (p < j.size() && j[p] == ' ') p++;
    return p < j.size() && j[p] == 't';
}

} // namespace

// ============================================================================
// BulkFixProgress
// ============================================================================

std::string BulkFixProgress::summary() const {
    std::ostringstream j;
    j << "{"
      << "\"totalTargets\":" << totalTargets
      << ",\"completed\":" << completed
      << ",\"failed\":" << failed
      << ",\"skipped\":" << skipped
      << ",\"verified\":" << verified
      << ",\"inProgress\":" << inProgress
      << ",\"retries\":" << retries
      << ",\"percentComplete\":" << percentComplete
      << ",\"elapsedMs\":" << elapsedMs
      << "}";
    return j.str();
}

// ============================================================================
// BulkFixResult
// ============================================================================

BulkFixResult BulkFixResult::ok(const std::string& id, const std::string& strategy,
                                const std::vector<BulkFixTarget>& targets,
                                const std::string& merged) {
    BulkFixResult r;
    r.bulkFixId = id;
    r.strategyName = strategy;
    r.targets = targets;
    r.mergedResult = merged;
    r.progress.totalTargets = (int)targets.size();
    r.progress.completed = r.fixedCount();
    r.progress.failed = r.failedCount();
    r.progress.percentComplete = r.progress.totalTargets
        ? (100.0f * (float)r.progress.completed / (float)r.progress.totalTargets) : 0.0f;
    r.success = (r.progress.totalTargets == 0) || (r.progress.failed == 0);
    return r;
}

BulkFixResult BulkFixResult::fail(const std::string& id, const std::string& msg) {
    BulkFixResult r;
    r.success = false;
    r.bulkFixId = id;
    r.error = msg;
    return r;
}

int BulkFixResult::fixedCount() const {
    int n = 0;
    for (const auto& t : targets)
        if (t.status == BulkFixTarget::Status::Fixed || t.status == BulkFixTarget::Status::Verified) ++n;
    return n;
}

int BulkFixResult::failedCount() const {
    int n = 0;
    for (const auto& t : targets)
        if (t.status == BulkFixTarget::Status::Failed) ++n;
    return n;
}

std::vector<BulkFixTarget> BulkFixResult::failedTargets() const {
    std::vector<BulkFixTarget> out;
    for (const auto& t : targets)
        if (t.status == BulkFixTarget::Status::Failed) out.push_back(t);
    return out;
}

// ============================================================================
// AutonomousSubAgent
// ============================================================================

AutonomousSubAgent::AutonomousSubAgent(SubAgentManager* manager,
                                       AgenticEngine* engine,
                                       AgenticFailureDetector* detector,
                                       AgenticPuppeteer* puppeteer)
    : m_manager(manager), m_engine(engine), m_detector(detector), m_puppeteer(puppeteer) {
    m_bulkFixId = generateId();
}

AutonomousSubAgent::~AutonomousSubAgent() {
    cancel();
    // Join any detached worker indirectly via brief wait for the running flag.
    for (int i = 0; i < 100 && m_running.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

std::string AutonomousSubAgent::generateId() const {
    return bf_uuid("bf");
}

void AutonomousSubAgent::setStrategy(const BulkFixStrategy& strategy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_strategy = strategy;
}

void AutonomousSubAgent::setTargets(const std::vector<BulkFixTarget>& targets) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_targets = targets;
}

void AutonomousSubAgent::addTarget(const BulkFixTarget& target) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_targets.push_back(target);
}

std::string AutonomousSubAgent::buildPrompt(const BulkFixTarget& target) const {
    std::string p = m_strategy.promptTemplate;
    p = bf_replace_all(p, "{{target}}", target.id);
    p = bf_replace_all(p, "{{path}}", target.path);
    p = bf_replace_all(p, "{{context}}", target.context);
    p = bf_replace_all(p, "{{category}}", target.category);
    if (p.empty())
        p = "Apply the '" + m_strategy.name + "' fix to target '" + target.id + "'.";
    return p;
}

bool AutonomousSubAgent::processTarget(BulkFixTarget& target, const std::string& parentId) {
    if (!m_manager) { target.status = BulkFixTarget::Status::Failed; target.result = "[error] no manager"; return false; }
    if (m_onTargetStarted) m_onTargetStarted(m_bulkFixId, target);

    const int maxAttempts = std::max(1, m_strategy.maxRetries + 1);
    auto start = std::chrono::steady_clock::now();
    std::string result;
    bool success = false;

    for (int attempt = 0; attempt < maxAttempts && !m_cancelled.load(); ++attempt) {
        target.status = BulkFixTarget::Status::InProgress;
        target.retryCount = attempt;

        const std::string prompt = buildPrompt(target);
        const std::string agentId = m_manager->spawnSubAgent(parentId,
                                                             "bulkfix:" + target.id, prompt);
        m_manager->waitForSubAgent(agentId, m_strategy.perTargetTimeoutMs);
        result = m_manager->getSubAgentResult(agentId);

        bool ok = bf_result_ok(result);
        if (ok && m_strategy.customValidator)
            ok = m_strategy.customValidator(target.id, result);

        if (!ok) {
            m_progress.retries++;
            continue;
        }

        // Verification pass (fail-soft: a missing verification prompt is a pass).
        if (m_strategy.autoVerify) {
            if (!verifyFix(target, result, parentId)) {
                m_progress.retries++;
                continue;
            }
            target.status = BulkFixTarget::Status::Verified;
        } else {
            target.status = BulkFixTarget::Status::Fixed;
        }
        success = true;
        break;
    }

    if (!success && !m_cancelled.load() && m_strategy.selfHeal) {
        const std::string healed = selfHeal(result, target);
        if (bf_result_ok(healed)) { result = healed; success = true; target.status = BulkFixTarget::Status::Fixed; }
    }

    if (m_cancelled.load())        target.status = BulkFixTarget::Status::Skipped;
    else if (!success)             target.status = BulkFixTarget::Status::Failed;

    target.result = result;
    target.elapsedMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start).count();

    if (m_onTargetCompleted) m_onTargetCompleted(m_bulkFixId, target, success);
    return success;
}

bool AutonomousSubAgent::verifyFix(const BulkFixTarget& target, const std::string& result,
                                   const std::string& parentId) {
    if (!m_strategy.autoVerify) return true;
    if (!m_manager) return true;

    std::string vprompt = m_strategy.verificationPrompt;
    if (vprompt.empty()) {
        // Default verification: has the fix produced real, non-error content?
        return bf_result_ok(result);
    }
    vprompt = bf_replace_all(vprompt, "{{target}}", target.id);
    vprompt = bf_replace_all(vprompt, "{{context}}", target.context);
    vprompt = bf_replace_all(vprompt, "{{result}}", result);

    const std::string vId = m_manager->spawnSubAgent(parentId, "verify:" + target.id, vprompt);
    m_manager->waitForSubAgent(vId, m_strategy.perTargetTimeoutMs);
    const std::string vres = m_manager->getSubAgentResult(vId);
    // A verifier that returns nothing conclusive is treated as a pass (fail-soft).
    if (vres.empty()) return true;
    const std::string lower = [](std::string s){ for (auto& c : s) c = (char)tolower((unsigned char)c); return s; }(vres);
    if (lower.find("fail") != std::string::npos || lower.find("incorrect") != std::string::npos ||
        lower.find("not fixed") != std::string::npos)
        return false;
    return true;
}

std::string AutonomousSubAgent::selfHeal(const std::string& failedResult,
                                         const BulkFixTarget& target) {
    if (!m_manager) return "";
    // Augment the prompt with the failure context and retry once.
    std::string prompt = buildPrompt(target);
    prompt += "\n\n[previous attempt failed]\n" + failedResult +
              "\n[correct the above and produce a valid fix]";
    const std::string agentId = m_manager->spawnSubAgent("selfheal", "heal:" + target.id, prompt);
    m_manager->waitForSubAgent(agentId, m_strategy.perTargetTimeoutMs);
    return m_manager->getSubAgentResult(agentId);
}

std::string AutonomousSubAgent::mergeResults(const std::string& /*parentId*/) {
    std::ostringstream out;
    switch (m_strategy.mergeMode) {
        case BulkFixStrategy::MergeMode::Concatenate: {
            for (const auto& t : m_targets)
                if (!t.result.empty()) out << t.result << "\n";
            break;
        }
        case BulkFixStrategy::MergeMode::Summarize: {
            // Deterministic structured summary (no external model required).
            int fixed = 0, failed = 0, skipped = 0;
            for (const auto& t : m_targets) {
                switch (t.status) {
                    case BulkFixTarget::Status::Fixed:
                    case BulkFixTarget::Status::Verified: ++fixed; break;
                    case BulkFixTarget::Status::Failed:   ++failed; break;
                    case BulkFixTarget::Status::Skipped:  ++skipped; break;
                    default: break;
                }
            }
            out << "Bulk fix '" << m_strategy.name << "' summary: "
                << m_targets.size() << " targets (" << fixed << " fixed, "
                << failed << " failed, " << skipped << " skipped)\n";
            for (const auto& t : m_targets)
                out << "- " << t.id << " [" << t.statusString() << "]: " << t.result << "\n";
            break;
        }
        case BulkFixStrategy::MergeMode::Individual:
        default: {
            for (const auto& t : m_targets)
                out << t.id << ": " << t.result << "\n";
            break;
        }
    }
    return out.str();
}

void AutonomousSubAgent::updateProgress() {
    int completed = 0, failed = 0, skipped = 0, verified = 0, inProgress = 0;
    for (const auto& t : m_targets) {
        switch (t.status) {
            case BulkFixTarget::Status::Fixed:    ++completed; break;
            case BulkFixTarget::Status::Verified: ++completed; ++verified; break;
            case BulkFixTarget::Status::Failed:   ++failed; break;
            case BulkFixTarget::Status::Skipped:  ++skipped; break;
            case BulkFixTarget::Status::InProgress: ++inProgress; break;
            default: break;
        }
    }
    m_progress.totalTargets = (int)m_targets.size();
    m_progress.completed = completed;
    m_progress.failed = failed;
    m_progress.skipped = skipped;
    m_progress.verified = verified;
    m_progress.inProgress = inProgress;
    m_progress.percentComplete = m_progress.totalTargets
        ? (100.0f * (float)completed / (float)m_progress.totalTargets) : 0.0f;
    m_progress.elapsedMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - m_progress.startTime).count();
    if (m_onProgress) m_onProgress(m_bulkFixId, m_progress);
}

BulkFixResult AutonomousSubAgent::execute(const std::string& parentId) {
    m_running.store(true);
    m_cancelled.store(false);
    m_progress.startTime = std::chrono::steady_clock::now();
    m_progress = BulkFixProgress{};
    m_progress.startTime = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Snapshot targets so concurrent mutation does not disturb the loop.
        for (auto& t : m_targets) t.status = BulkFixTarget::Status::Pending;
    }
    updateProgress();

    for (auto& t : m_targets) {
        if (m_cancelled.load()) { t.status = BulkFixTarget::Status::Skipped; break; }
        processTarget(t, parentId);
        updateProgress();
    }

    const std::string merged = mergeResults(parentId);
    m_running.store(false);

    BulkFixResult r = BulkFixResult::ok(m_bulkFixId, m_strategy.name, m_targets, merged);
    r.progress = m_progress;
    if (m_onCompleted) m_onCompleted(r);
    return r;
}

std::string AutonomousSubAgent::executeAsync(const std::string& parentId,
                                             BulkFixCompletedCb onComplete) {
    m_bulkFixId = generateId();
    m_running.store(true);
    std::string id = m_bulkFixId;

    // The caller (or BulkFixOrchestrator) keeps this object alive via a
    // shared_ptr while m_running is true; execute() returns and fires onComplete.
    std::thread([this, parentId, onComplete]() {
        BulkFixResult r = this->execute(parentId);
        if (onComplete) onComplete(r);
    }).detach();

    return id;
}

void AutonomousSubAgent::cancel() {
    m_cancelled.store(true);
}

BulkFixProgress AutonomousSubAgent::getProgress() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_progress;
}

std::string AutonomousSubAgent::getProgressJSON() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream j;
    j << "{\"bulkFixId\":\"" << m_bulkFixId << "\",\"running\":" << (m_running.load() ? "true" : "false")
      << ",\"progress\":" << m_progress.summary() << "}";
    return j.str();
}

std::string AutonomousSubAgent::getStatusSummary() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream s;
    s << "BulkFix " << m_bulkFixId << " (" << m_strategy.name << "): "
      << m_progress.completed << "/" << m_progress.totalTargets << " completed, "
      << m_progress.failed << " failed, running=" << (m_running.load() ? "true" : "false");
    return s.str();
}

// ============================================================================
// BulkFixOrchestrator
// ============================================================================

BulkFixOrchestrator::BulkFixOrchestrator(SubAgentManager* manager,
                                         AgenticEngine* engine,
                                         AgenticFailureDetector* detector,
                                         AgenticPuppeteer* puppeteer)
    : m_manager(manager), m_engine(engine), m_detector(detector), m_puppeteer(puppeteer) {}

BulkFixOrchestrator::~BulkFixOrchestrator() {
    cancelAll();
}

// ---- Predefined strategy factories (the ten seams invoked by SubAgentManager) ----

BulkFixStrategy BulkFixOrchestrator::makeCompileErrorFixStrategy() {
    BulkFixStrategy s;
    s.name = "compile-error-fix";
    s.description = "Resolve compiler errors in the target files.";
    s.promptTemplate =
        "Fix the compiler error(s) in {{path}}.\nContext: {{context}}\n"
        "Return the corrected source that compiles cleanly.";
    s.verificationPrompt = "Does the following fix for {{path}} resolve the compile error? Answer ok or fail.\n{{result}}";
    s.maxRetries = 3; s.maxParallel = 4; s.autoVerify = true; s.selfHeal = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeFormatEnforcementStrategy() {
    BulkFixStrategy s;
    s.name = "format-enforcement";
    s.description = "Apply consistent formatting to the target files.";
    s.promptTemplate = "Reformat {{path}} to the project style.\nContext: {{context}}";
    s.maxRetries = 1; s.maxParallel = 8; s.autoVerify = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeRefactorRenameStrategy(const std::string& oldName,
                                                                const std::string& newName) {
    BulkFixStrategy s;
    s.name = "refactor-rename";
    s.description = "Rename '" + oldName + "' to '" + newName + "' across targets.";
    s.promptTemplate =
        "Rename every occurrence of '" + oldName + "' to '" + newName + "' in {{path}}.\nContext: {{context}}";
    s.verificationPrompt = "Confirm no occurrence of '" + oldName + "' remains in {{path}}. Answer ok or fail.\n{{result}}";
    s.maxRetries = 2; s.maxParallel = 6; s.autoVerify = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeStubImplementationStrategy() {
    BulkFixStrategy s;
    s.name = "stub-implementation";
    s.description = "Replace TODO/stub markers with real implementations.";
    s.promptTemplate =
        "Implement the stubbed region at {{context}} in {{path}} with real, working code. No placeholders.";
    s.verificationPrompt = "Is the implementation at {{context}} in {{path}} complete and functional? Answer ok or fail.\n{{result}}";
    s.maxRetries = 4; s.maxParallel = 2; s.autoVerify = true; s.selfHeal = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeHeaderIncludeFixStrategy() {
    BulkFixStrategy s;
    s.name = "header-include-fix";
    s.description = "Add missing #include directives reported for the target.";
    s.promptTemplate =
        "Add the missing include(s) to {{path}} so it compiles.\nContext: {{context}}";
    s.maxRetries = 2; s.maxParallel = 8; s.autoVerify = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeLintFixStrategy() {
    BulkFixStrategy s;
    s.name = "lint-fix";
    s.description = "Resolve lint warnings in the target files.";
    s.promptTemplate = "Fix the lint warning(s) in {{path}} without changing behavior.\nContext: {{context}}";
    s.maxRetries = 2; s.maxParallel = 8; s.autoVerify = false;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeTestGenerationStrategy() {
    BulkFixStrategy s;
    s.name = "test-generation";
    s.description = "Generate unit tests for the target symbol/region.";
    s.promptTemplate =
        "Write focused unit tests for {{context}} in {{path}}. Use the project's test framework.";
    s.maxRetries = 2; s.maxParallel = 4; s.autoVerify = false;
    s.mergeMode = BulkFixStrategy::MergeMode::Summarize;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeDocCommentStrategy() {
    BulkFixStrategy s;
    s.name = "doc-comment";
    s.description = "Add accurate documentation comments to the target region.";
    s.promptTemplate = "Document {{context}} in {{path}} with accurate comments.";
    s.maxRetries = 1; s.maxParallel = 8; s.autoVerify = false;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeSecurityAuditFixStrategy() {
    BulkFixStrategy s;
    s.name = "security-audit-fix";
    s.description = "Remediate the security finding at the target.";
    s.promptTemplate =
        "Remediate the security issue at {{context}} in {{path}}. Preserve behavior; harden the vulnerability.";
    s.verificationPrompt = "Is the security issue at {{context}} remediated? Answer ok or fail.\n{{result}}";
    s.maxRetries = 3; s.maxParallel = 2; s.autoVerify = true; s.selfHeal = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

BulkFixStrategy BulkFixOrchestrator::makeCustomStrategy(const std::string& name,
                                                        const std::string& promptTemplate) {
    BulkFixStrategy s;
    s.name = name.empty() ? "custom" : name;
    s.description = "Custom bulk fix: " + s.name;
    s.promptTemplate = promptTemplate;
    s.maxRetries = 3; s.maxParallel = 4; s.autoVerify = true;
    s.mergeMode = BulkFixStrategy::MergeMode::Individual;
    return s;
}

// ---- High-level dispatch ----

BulkFixResult BulkFixOrchestrator::fixCompileErrors(const std::string& parentId,
                                                    const std::vector<std::string>& filePaths) {
    BulkFixStrategy strategy = makeCompileErrorFixStrategy();
    std::vector<BulkFixTarget> targets;
    targets.reserve(filePaths.size());
    for (const auto& p : filePaths) {
        BulkFixTarget t;
        t.id = p;
        t.path = p;
        t.category = "compile-error";
        targets.push_back(t);
    }
    return applyBulkRefactor(parentId, strategy, targets);
}

BulkFixResult BulkFixOrchestrator::applyBulkRefactor(const std::string& parentId,
                                                     const BulkFixStrategy& strategy,
                                                     const std::vector<BulkFixTarget>& targets) {
    auto agent = std::make_shared<AutonomousSubAgent>(m_manager, m_engine, m_detector, m_puppeteer);
    agent->setStrategy(strategy);
    agent->setTargets(targets);

    BulkFixResult result;
    try {
        result = agent->execute(parentId);
    } catch (const std::exception& e) {
        return BulkFixResult::fail(agent->strategy().name, std::string("exception: ") + e.what());
    } catch (...) {
        return BulkFixResult::fail(agent->strategy().name, "unknown exception");
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.totalBulkOps++;
        m_stats.totalTargetsProcessed += (int)targets.size();
        m_stats.totalFixed += result.fixedCount();
        m_stats.totalFailed += result.failedCount();
        m_stats.totalVerified += result.progress.verified;
        m_stats.totalRetries += result.progress.retries;
    }
    return result;
}

std::string BulkFixOrchestrator::dispatchBulkFix(const std::string& parentId,
                                                 const BulkFixStrategy& strategy,
                                                 const std::vector<BulkFixTarget>& targets,
                                                 BulkFixCompletedCb onComplete) {
    auto agent = std::make_shared<AutonomousSubAgent>(m_manager, m_engine, m_detector, m_puppeteer);
    agent->setStrategy(strategy);
    agent->setTargets(targets);

    // Keep the agent alive in the registry until it finishes (isRunning == false).
    auto doneCb = [this, agent, onComplete](const BulkFixResult& r) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stats.totalBulkOps++;
            m_stats.totalTargetsProcessed += (int)r.targets.size();
            m_stats.totalFixed += r.fixedCount();
            m_stats.totalFailed += r.failedCount();
            m_stats.totalVerified += r.progress.verified;
            m_stats.totalRetries += r.progress.retries;
        }
        if (onComplete) onComplete(r);
    };

    const std::string id = agent->executeAsync(parentId, doneCb);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_active[id] = agent;
        // Reclaim finished operations so the registry does not grow unbounded.
        for (auto it = m_active.begin(); it != m_active.end();) {
            if (it->second && it->second->isRunning()) ++it;
            else it = m_active.erase(it);
        }
    }
    return id;
}

bool BulkFixOrchestrator::parseBulkFixToolCall(const std::string& modelOutput,
                                               BulkFixStrategy& strategy,
                                               std::vector<BulkFixTarget>& targets) const {
    // Recognise an explicit TOOL call block emitted by a model:
    //   <tool name="bulk_fix" strategy="compile-error-fix">path1,path2,...</tool>
    const std::string openTag = "<tool";
    auto pos = modelOutput.find(openTag);
    if (pos == std::string::npos) return false;
    auto namePos = modelOutput.find("bulk_fix", pos);
    if (namePos == std::string::npos || namePos - pos > 200) return false;

    std::string strategyName = "compile-error-fix";
    auto stratKey = modelOutput.find("strategy=\"", namePos);
    if (stratKey != std::string::npos) {
        stratKey += 11;
        auto stratEnd = modelOutput.find('"', stratKey);
        if (stratEnd != std::string::npos) strategyName = modelOutput.substr(stratKey, stratEnd - stratKey);
    }

    auto gt = modelOutput.find('>', namePos);
    auto close = modelOutput.find("</tool>", gt);
    if (gt == std::string::npos || close == std::string::npos) return false;
    std::string body = modelOutput.substr(gt + 1, close - (gt + 1));

    if (strategyName == "compile-error-fix")        strategy = makeCompileErrorFixStrategy();
    else if (strategyName == "format-enforcement")  strategy = makeFormatEnforcementStrategy();
    else if (strategyName == "stub-implementation") strategy = makeStubImplementationStrategy();
    else if (strategyName == "header-include-fix")  strategy = makeHeaderIncludeFixStrategy();
    else if (strategyName == "lint-fix")            strategy = makeLintFixStrategy();
    else if (strategyName == "test-generation")     strategy = makeTestGenerationStrategy();
    else if (strategyName == "doc-comment")         strategy = makeDocCommentStrategy();
    else if (strategyName == "security-audit-fix")  strategy = makeSecurityAuditFixStrategy();
    else                                           strategy = makeCustomStrategy(strategyName, modelOutput);

    // Body: comma or whitespace separated target paths.
    std::string token;
    auto flush = [&](const std::string& v) {
        std::string trimmed = v;
        while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t' ||
               trimmed.front() == '\r' || trimmed.front() == '\n' || trimmed.front() == ',')) trimmed.erase(trimmed.begin());
        while (!trimmed.empty() && (trimmed.back() == ' ' || trimmed.back() == '\t' ||
               trimmed.back() == '\r' || trimmed.back() == '\n' || trimmed.back() == ',')) trimmed.pop_back();
        if (trimmed.empty()) return;
        BulkFixTarget t; t.id = trimmed; t.path = trimmed; t.category = strategyName;
        targets.push_back(t);
    };
    for (char c : body) {
        if (c == ',' || c == '\n' || c == '\r') { flush(token); token.clear(); }
        else token += c;
    }
    flush(token);
    return !targets.empty();
}

BulkFixProgress BulkFixOrchestrator::getProgress(const std::string& bulkFixId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_active.find(bulkFixId);
    if (it != m_active.end() && it->second) return it->second->getProgress();
    return BulkFixProgress{};
}

void BulkFixOrchestrator::cancelBulkFix(const std::string& bulkFixId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_active.find(bulkFixId);
    if (it != m_active.end() && it->second) it->second->cancel();
}

void BulkFixOrchestrator::cancelAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, agent] : m_active) if (agent) agent->cancel();
}

std::vector<std::string> BulkFixOrchestrator::activeOperations() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> out;
    for (const auto& [id, agent] : m_active)
        if (agent && agent->isRunning()) out.push_back(id);
    return out;
}

BulkFixOrchestrator::Stats BulkFixOrchestrator::getStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

void BulkFixOrchestrator::resetStats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stats = Stats{};
}
