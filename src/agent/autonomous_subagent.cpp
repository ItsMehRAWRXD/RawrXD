// =============================================================================
// autonomous_subagent.cpp — BulkFixOrchestrator + AutonomousSubAgent (real).
// =============================================================================
// Fail-closed bulk refactor: with no AgenticEngine every target is reported
// failed with an explicit reason; with an engine, each target's file is read,
// the strategy prompt is rendered ({{path}}/{{context}}/{{content}}), the
// model's answer is written back, and the verdict recorded per target.
// Self-healing = one retry with the failure appended to the prompt.
// =============================================================================
#include "autonomous_subagent.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>

#include "../agentic/agentic_engine_iface.h"

namespace {

std::string ReadFileOrEmpty(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string ReplaceAll(std::string s, const std::string& from,
                       const std::string& to) {
    if (from.empty()) return s;
    size_t p = 0;
    while ((p = s.find(from, p)) != std::string::npos) {
        s.replace(p, from.size(), to);
        p += to.size();
    }
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// BulkFixProgress / BulkFixResult
// ---------------------------------------------------------------------------
std::string BulkFixProgress::summary() const {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "%d/%d done, %d failed, %d%%", completed,
                  totalTargets, failed, (int)percentComplete);
    return buf;
}

BulkFixResult BulkFixResult::ok(const std::string& id,
                                const std::string& strategy,
                                const std::vector<BulkFixTarget>& targets,
                                const std::string& merged) {
    BulkFixResult r;
    r.success = true;
    r.bulkFixId = id;
    r.strategyName = strategy;
    r.targets = targets;
    r.mergedResult = merged;
    r.progress.totalTargets = (int)targets.size();
    for (const auto& t : targets) {
        if (t.status == BulkFixTarget::Status::Fixed) {
            r.progress.completed++;
            r.progress.verified +=
                (t.status == BulkFixTarget::Status::Verified) ? 1 : 0;
        } else if (t.status == BulkFixTarget::Status::Failed) {
            r.progress.failed++;
        } else if (t.status == BulkFixTarget::Status::Skipped) {
            r.progress.skipped++;
        }
    }
    return r;
}

BulkFixResult BulkFixResult::fail(const std::string& id,
                                  const std::string& msg) {
    BulkFixResult r;
    r.success = false;
    r.bulkFixId = id;
    r.error = msg;
    return r;
}

int BulkFixResult::fixedCount() const {
    return (int)std::count_if(targets.begin(), targets.end(),
                              [](const BulkFixTarget& t) {
                                  return t.status ==
                                             BulkFixTarget::Status::Fixed ||
                                         t.status ==
                                             BulkFixTarget::Status::Verified;
                              });
}

int BulkFixResult::failedCount() const {
    return (int)std::count_if(targets.begin(), targets.end(),
                              [](const BulkFixTarget& t) {
                                  return t.status ==
                                         BulkFixTarget::Status::Failed;
                              });
}

std::vector<BulkFixTarget> BulkFixResult::failedTargets() const {
    std::vector<BulkFixTarget> out;
    for (const auto& t : targets)
        if (t.status == BulkFixTarget::Status::Failed) out.push_back(t);
    return out;
}

// ---------------------------------------------------------------------------
// Strategy factories
// ---------------------------------------------------------------------------
BulkFixStrategy BulkFixOrchestrator::makeCompileErrorFixStrategy() {
    BulkFixStrategy s;
    s.name = "compile_error_fix";
    s.description = "Fix compile errors";
    s.promptTemplate =
        "Fix the compile error in {{path}}.\nContext: {{context}}\n"
        "Return the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeFormatEnforcementStrategy() {
    BulkFixStrategy s;
    s.name = "format_enforcement";
    s.description = "Reformat to project style";
    s.promptTemplate =
        "Reformat {{path}} to the project style. Context: {{context}}\n"
        "Return the formatted file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeRefactorRenameStrategy(
    const std::string& oldName, const std::string& newName) {
    BulkFixStrategy s;
    s.name = "refactor_rename";
    s.description = "Rename " + oldName + " to " + newName;
    s.promptTemplate = "Rename all occurrences of " + oldName + " to " +
                       newName + " in {{path}}. Context: {{context}}\n"
                       "Return the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeStubImplementationStrategy() {
    BulkFixStrategy s;
    s.name = "stub_implementation";
    s.description = "Replace stubs with real code";
    s.promptTemplate =
        "Replace stubs in {{path}} with real implementations. "
        "Context: {{context}}\nReturn the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeHeaderIncludeFixStrategy() {
    BulkFixStrategy s;
    s.name = "header_include_fix";
    s.description = "Fix missing includes";
    s.promptTemplate = "Fix missing includes in {{path}}. Context: "
                       "{{context}}\nReturn the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeLintFixStrategy() {
    BulkFixStrategy s;
    s.name = "lint_fix";
    s.description = "Fix lint findings";
    s.promptTemplate = "Fix lint findings in {{path}}. Context: {{context}}\n"
                       "Return the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeTestGenerationStrategy() {
    BulkFixStrategy s;
    s.name = "test_generation";
    s.description = "Generate unit tests";
    s.promptTemplate = "Generate unit tests for {{path}}. Context: "
                       "{{context}}\nReturn the test file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeDocCommentStrategy() {
    BulkFixStrategy s;
    s.name = "doc_comments";
    s.description = "Add documentation comments";
    s.promptTemplate =
        "Add documentation comments to {{path}}. Context: {{context}}\n"
        "Return the documented file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeSecurityAuditFixStrategy() {
    BulkFixStrategy s;
    s.name = "security_audit_fix";
    s.description = "Fix security findings";
    s.promptTemplate = "Fix security findings in {{path}}. Context: "
                       "{{context}}\nReturn the corrected file content only.\n";
    return s;
}
BulkFixStrategy BulkFixOrchestrator::makeCustomStrategy(
    const std::string& name, const std::string& promptTemplate) {
    BulkFixStrategy s;
    s.name = name;
    s.description = name;
    s.promptTemplate = promptTemplate;
    return s;
}

// ---------------------------------------------------------------------------
// BulkFixOrchestrator
// ---------------------------------------------------------------------------
BulkFixOrchestrator::BulkFixOrchestrator(SubAgentManager* manager,
                                         AgenticEngine* engine,
                                         AgenticFailureDetector* detector,
                                         AgenticPuppeteer* puppeteer)
    : m_manager(manager), m_engine(engine), m_detector(detector),
      m_puppeteer(puppeteer) {}

BulkFixOrchestrator::~BulkFixOrchestrator() { cancelAll(); }

BulkFixResult BulkFixOrchestrator::applyBulkRefactor(
    const std::string& parentId, const BulkFixStrategy& strategy,
    const std::vector<BulkFixTarget>& targets) {
    (void)parentId;
    BulkFixResult result;
    result.bulkFixId = "bulk_" + std::to_string(m_stats.totalBulkOps + 1);
    result.strategyName = strategy.name;
    result.targets = targets;
    m_stats.totalBulkOps++;

    if (!m_engine) {
        // Fail closed: never fabricate fixed files.
        for (auto& t : result.targets) {
            t.status = BulkFixTarget::Status::Failed;
            t.result = "No AgenticEngine available";
        }
        result.success = false;
        result.error = "No AgenticEngine available";
        result.progress.totalTargets = (int)targets.size();
        result.progress.failed = (int)targets.size();
        m_stats.totalFailed += (int)targets.size();
        return result;
    }

    int fixed = 0, failed = 0;
    for (auto& t : result.targets) {
        const std::string content = ReadFileOrEmpty(t.path);
        if (content.empty()) {
            t.status = BulkFixTarget::Status::Failed;
            t.result = "unreadable";
            ++failed;
            continue;
        }
        std::string prompt = ReplaceAll(strategy.promptTemplate, "{{path}}",
                                        t.path);
        prompt = ReplaceAll(prompt, "{{context}}", t.context);
        prompt = ReplaceAll(prompt, "{{content}}", content);
        std::string answer;
        try {
            answer = m_engine->chat(prompt);
        } catch (const std::exception& e) {
            t.status = BulkFixTarget::Status::Failed;
            t.result = std::string("engine error: ") + e.what();
            ++failed;
            continue;
        }
        if (answer.empty()) {
            t.status = BulkFixTarget::Status::Failed;
            t.result = "empty model response";
            ++failed;
            continue;
        }
        std::ofstream out(t.path, std::ios::binary);
        if (!out) {
            t.status = BulkFixTarget::Status::Failed;
            t.result = "write failed";
            ++failed;
            continue;
        }
        out << answer;
        t.status = BulkFixTarget::Status::Fixed;
        ++fixed;
    }
    result.progress.totalTargets = (int)result.targets.size();
    result.progress.completed = fixed;
    result.progress.failed = failed;
    result.progress.percentComplete =
        result.progress.totalTargets > 0
            ? (100.0f * fixed / result.progress.totalTargets)
            : 0.0f;
    result.success = failed == 0;
    m_stats.totalTargetsProcessed += (int)result.targets.size();
    m_stats.totalFixed += fixed;
    m_stats.totalFailed += failed;
    return result;
}

BulkFixResult BulkFixOrchestrator::fixCompileErrors(
    const std::string& parentId, const std::vector<std::string>& filePaths) {
    std::vector<BulkFixTarget> targets;
    for (size_t i = 0; i < filePaths.size(); ++i)
        targets.push_back({"t" + std::to_string(i), filePaths[i], "", ""});
    return applyBulkRefactor(parentId, makeCompileErrorFixStrategy(), targets);
}

std::string BulkFixOrchestrator::dispatchBulkFix(
    const std::string& parentId, const BulkFixStrategy& strategy,
    const std::vector<BulkFixTarget>& targets, BulkFixCompletedCb onComplete) {
    auto agent = std::make_shared<AutonomousSubAgent>(
        m_manager, m_engine, m_detector, m_puppeteer);
    agent->setStrategy(strategy);
    agent->setTargets(targets);
    const std::string id = agent->executeAsync(parentId, onComplete);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_active[id] = agent;
    return id;
}

bool BulkFixOrchestrator::parseBulkFixToolCall(
    const std::string& modelOutput, BulkFixStrategy& strategy,
    std::vector<BulkFixTarget>& targets) const {
    std::istringstream in(modelOutput);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("STRATEGY ", 0) == 0) {
            strategy.name = line.substr(9);
            strategy.promptTemplate =
                "Apply the fix to {{path}}. Context: {{context}}\n"
                "Return the corrected file content only.\n";
        } else if (line.rfind("TARGET ", 0) == 0) {
            targets.push_back({"t" + std::to_string(targets.size()),
                               line.substr(7), "", ""});
        }
    }
    return !targets.empty();
}

BulkFixProgress BulkFixOrchestrator::getProgress(
    const std::string& bulkFixId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_active.find(bulkFixId);
    if (it == m_active.end()) return {};
    return it->second->getProgress();
}

void BulkFixOrchestrator::cancelBulkFix(const std::string& bulkFixId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_active.find(bulkFixId);
    if (it != m_active.end()) it->second->cancel();
}

void BulkFixOrchestrator::cancelAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, agent] : m_active) agent->cancel();
}

std::vector<std::string> BulkFixOrchestrator::activeOperations() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> out;
    for (const auto& [id, agent] : m_active) {
        if (agent->isRunning()) out.push_back(id);
    }
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

// ---------------------------------------------------------------------------
// AutonomousSubAgent
// ---------------------------------------------------------------------------
AutonomousSubAgent::AutonomousSubAgent(SubAgentManager* manager,
                                       AgenticEngine* engine,
                                       AgenticFailureDetector* detector,
                                       AgenticPuppeteer* puppeteer)
    : m_manager(manager), m_engine(engine), m_detector(detector),
      m_puppeteer(puppeteer) {}

AutonomousSubAgent::~AutonomousSubAgent() { cancel(); }

void AutonomousSubAgent::setStrategy(const BulkFixStrategy& strategy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_strategy = strategy;
}

void AutonomousSubAgent::setTargets(
    const std::vector<BulkFixTarget>& targets) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_targets = targets;
}

void AutonomousSubAgent::addTarget(const BulkFixTarget& target) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_targets.push_back(target);
}

std::string AutonomousSubAgent::buildPrompt(
    const BulkFixTarget& target) const {
    std::string prompt = ReplaceAll(m_strategy.promptTemplate, "{{path}}",
                                    target.path);
    prompt = ReplaceAll(prompt, "{{context}}", target.context);
    const std::string content = ReadFileOrEmpty(target.path);
    prompt = ReplaceAll(prompt, "{{content}}", content);
    return prompt;
}

bool AutonomousSubAgent::verifyFix(const BulkFixTarget& target,
                                   const std::string& result,
                                   const std::string& parentId) {
    (void)result;
    (void)parentId;
    if (m_strategy.customValidator)
        return m_strategy.customValidator(target.path, result);
    // Default verification: the file is readable and non-empty after the fix.
    return !ReadFileOrEmpty(target.path).empty();
}

std::string AutonomousSubAgent::selfHeal(const std::string& failedResult,
                                         const BulkFixTarget& target) {
    // Real self-healing without external services: one retry with the failure
    // appended to the prompt.
    if (!m_engine) return failedResult;
    std::string prompt = buildPrompt(target);
    prompt += "\nThe previous attempt failed: " + failedResult +
              "\nFix it and return the corrected file content only.\n";
    try {
        return m_engine->chat(prompt);
    } catch (...) {
        return failedResult;
    }
}

bool AutonomousSubAgent::processTarget(BulkFixTarget& target,
                                       const std::string& parentId) {
    if (!m_engine) {
        target.status = BulkFixTarget::Status::Failed;
        target.result = "No AgenticEngine available";
        return false;
    }
    if (m_onTargetStarted) m_onTargetStarted(m_bulkFixId, target);
    target.status = BulkFixTarget::Status::InProgress;

    std::string answer;
    try {
        answer = m_engine->chat(buildPrompt(target));
    } catch (const std::exception& e) {
        answer = selfHeal(std::string("engine error: ") + e.what(), target);
    }

    if (answer.empty() || !verifyFix(target, answer, parentId)) {
        // One self-heal retry.
        answer = selfHeal(answer.empty() ? "empty response" : answer, target);
    }

    bool ok = false;
    if (!answer.empty()) {
        std::ofstream out(target.path, std::ios::binary);
        if (out) {
            out << answer;
            ok = verifyFix(target, answer, parentId);
        }
    }
    target.status = ok ? BulkFixTarget::Status::Fixed
                       : BulkFixTarget::Status::Failed;
    if (!ok && target.result.empty())
        target.result = "fix not verified";
    if (m_onTargetCompleted) m_onTargetCompleted(m_bulkFixId, target, ok);
    updateProgress();
    return ok;
}

std::string AutonomousSubAgent::mergeResults(const std::string& parentId) {
    (void)parentId;
    std::string merged;
    for (const auto& t : m_targets) {
        if (m_strategy.mergeMode == BulkFixStrategy::MergeMode::Individual) {
            merged += t.path + ": " + t.statusString() + "\n";
        } else {
            merged += t.result + "\n";
        }
    }
    return merged;
}

void AutonomousSubAgent::updateProgress() {
    m_progress.totalTargets = (int)m_targets.size();
    m_progress.completed = 0;
    m_progress.failed = 0;
    for (const auto& t : m_targets) {
        if (t.status == BulkFixTarget::Status::Fixed ||
            t.status == BulkFixTarget::Status::Verified)
            m_progress.completed++;
        else if (t.status == BulkFixTarget::Status::Failed)
            m_progress.failed++;
    }
    m_progress.percentComplete = m_progress.totalTargets > 0
        ? (100.0f * m_progress.completed / m_progress.totalTargets)
        : 0.0f;
    if (m_onProgress) m_onProgress(m_bulkFixId, m_progress);
}

std::string AutonomousSubAgent::generateId() const {
    static std::atomic<int> counter{0};
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    char buf[48];
    std::snprintf(buf, sizeof(buf), "agent_%lld_%d",
                  (long long)now.count(), counter++);
    return buf;
}

BulkFixResult AutonomousSubAgent::execute(const std::string& parentId) {
    m_running.store(true);
    m_cancelled.store(false);
    m_bulkFixId = generateId();
    updateProgress();

    for (auto& t : m_targets) {
        if (m_cancelled.load()) {
            t.status = BulkFixTarget::Status::Skipped;
            continue;
        }
        processTarget(t, parentId);
        if (m_strategy.failFast && t.status == BulkFixTarget::Status::Failed)
            break;
    }

    std::string merged = mergeResults(parentId);
    BulkFixResult result = BulkFixResult::ok(m_bulkFixId, m_strategy.name,
                                             m_targets, merged);
    if (result.failedCount() > 0)
        result.success = false;
    m_progress.elapsedMs = 0;
    m_running.store(false);
    if (m_onCompleted) m_onCompleted(result);
    return result;
}

std::string AutonomousSubAgent::executeAsync(const std::string& parentId,
                                             BulkFixCompletedCb onComplete) {
    m_bulkFixId = generateId();
    const std::string id = m_bulkFixId;
    std::thread([this, parentId, onComplete]() {
        auto result = execute(parentId);
        if (onComplete) onComplete(result);
    }).detach();
    return id;
}

void AutonomousSubAgent::cancel() { m_cancelled.store(true); }

BulkFixProgress AutonomousSubAgent::getProgress() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_progress;
}

std::string AutonomousSubAgent::getProgressJSON() const {
    const auto p = getProgress();
    char buf[192];
    std::snprintf(buf, sizeof(buf),
                  "{\"total\":%d,\"completed\":%d,\"failed\":%d,"
                  "\"percent\":%.1f}",
                  p.totalTargets, p.completed, p.failed, p.percentComplete);
    return buf;
}

std::string AutonomousSubAgent::getStatusSummary() const {
    const auto p = getProgress();
    return p.summary();
}