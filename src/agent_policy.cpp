// ============================================================================
// agent_policy.cpp — Adaptive Intelligence & Policy Layer (implementation)
// ============================================================================
// Real, self-contained policy evaluation, heuristics, suggestions, persistence.
// "iptables for agent behavior." Every policy is opt-in; suggestions never
// auto-apply. No ML / RL / opaque scoring. Mutex-locked, thread-safe.
// Pure C++20 — no external dependencies (manual JSON, like agent_history.cpp).
// ============================================================================

#include "agent_policy.h"
#include "agent_history.h"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Small JSON helpers (self-contained; no third-party JSON library)
// ---------------------------------------------------------------------------
namespace {
std::string pol_escape(const std::string& s) {
    std::string out; out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", (int)(unsigned char)c);
                    out += buf;
                } else out += c;
        }
    }
    return out;
}
std::string pol_field(const std::string& json, const std::string& key) {
    // Returns raw value text after "key": (string or number/bool). Empty if absent.
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ')) pos++;
    if (pos < json.size() && json[pos] == '"') {
        // string value — parse with escapes
        pos++;
        std::string val;
        for (size_t i = pos; i < json.size(); ++i) {
            if (json[i] == '\\' && i + 1 < json.size()) {
                switch (json[i + 1]) {
                    case '\\': val += '\\'; i++; break;
                    case '"':  val += '"';  i++; break;
                    case 'n':  val += '\n'; i++; break;
                    case 'r':  val += '\r'; i++; break;
                    case 't':  val += '\t'; i++; break;
                    default:   val += json[i]; break;
                }
            } else if (json[i] == '"') break;
            else val += json[i];
        }
        return val;
    }
    // primitive value — read until delimiter
    std::string val;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != ' ') {
        val += json[pos++];
    }
    return val;
}
bool pol_contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    return haystack.find(needle) != std::string::npos;
}
} // namespace

// ============================================================================
// PolicyTrigger / PolicyAction / AgentPolicy / PolicySuggestion / Heuristic JSON
// ============================================================================

std::string PolicyTrigger::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"eventType\":\"" << pol_escape(eventType) << "\""
      << ",\"failureReason\":\"" << pol_escape(failureReason) << "\""
      << ",\"taskPattern\":\"" << pol_escape(taskPattern) << "\""
      << ",\"toolName\":\"" << pol_escape(toolName) << "\""
      << ",\"failureRateAbove\":" << failureRateAbove
      << ",\"minOccurrences\":" << minOccurrences
      << "}";
    return j.str();
}

PolicyTrigger PolicyTrigger::fromJSON(const std::string& json) {
    PolicyTrigger t;
    t.eventType     = pol_field(json, "eventType");
    t.failureReason = pol_field(json, "failureReason");
    t.taskPattern   = pol_field(json, "taskPattern");
    t.toolName      = pol_field(json, "toolName");
    if (!pol_field(json, "failureRateAbove").empty()) t.failureRateAbove = std::stof(pol_field(json, "failureRateAbove"));
    if (!pol_field(json, "minOccurrences").empty())   t.minOccurrences   = std::stoi(pol_field(json, "minOccurrences"));
    return t;
}

std::string PolicyAction::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"maxRetries\":" << maxRetries
      << ",\"retryDelayMs\":" << retryDelayMs
      << ",\"preferChainOverSwarm\":" << (preferChainOverSwarm ? "true" : "false")
      << ",\"reduceParallelism\":" << reduceParallelism
      << ",\"timeoutOverrideMs\":" << timeoutOverrideMs
      << ",\"confidenceThreshold\":" << confidenceThreshold
      << ",\"addValidationStep\":" << (addValidationStep ? "true" : "false")
      << ",\"validationPrompt\":\"" << pol_escape(validationPrompt) << "\""
      << ",\"customAction\":\"" << pol_escape(customAction) << "\""
      << "}";
    return j.str();
}

PolicyAction PolicyAction::fromJSON(const std::string& json) {
    PolicyAction a;
    auto i = [&](const char* k, int def)->int { auto v = pol_field(json, k); return v.empty() ? def : std::stoi(v); };
    auto b = [&](const char* k, bool def)->bool { auto v = pol_field(json, k); return v.empty() ? def : (v == "true"); };
    auto f = [&](const char* k, float def)->float { auto v = pol_field(json, k); return v.empty() ? def : std::stof(v); };
    a.maxRetries             = i("maxRetries", -1);
    a.retryDelayMs           = i("retryDelayMs", -1);
    a.preferChainOverSwarm   = b("preferChainOverSwarm", false);
    a.reduceParallelism      = i("reduceParallelism", 0);
    a.timeoutOverrideMs      = i("timeoutOverrideMs", -1);
    a.confidenceThreshold    = f("confidenceThreshold", -1.0f);
    a.addValidationStep      = b("addValidationStep", false);
    a.validationPrompt       = pol_field(json, "validationPrompt");
    a.customAction           = pol_field(json, "customAction");
    return a;
}

std::string AgentPolicy::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"id\":\"" << pol_escape(id) << "\""
      << ",\"name\":\"" << pol_escape(name) << "\""
      << ",\"description\":\"" << pol_escape(description) << "\""
      << ",\"version\":" << version
      << ",\"trigger\":" << trigger.toJSON()
      << ",\"action\":" << action.toJSON()
      << ",\"enabled\":" << (enabled ? "true" : "false")
      << ",\"requiresUserApproval\":" << (requiresUserApproval ? "true" : "false")
      << ",\"priority\":" << priority
      << ",\"createdAt\":" << createdAt
      << ",\"modifiedAt\":" << modifiedAt
      << ",\"createdBy\":\"" << pol_escape(createdBy) << "\""
      << ",\"appliedCount\":" << appliedCount
      << "}";
    return j.str();
}

AgentPolicy AgentPolicy::fromJSON(const std::string& json) {
    AgentPolicy p;
    p.id              = pol_field(json, "id");
    p.name            = pol_field(json, "name");
    p.description     = pol_field(json, "description");
    if (!pol_field(json, "version").empty()) p.version = std::stoi(pol_field(json, "version"));
    p.trigger         = PolicyTrigger::fromJSON(pol_field(json, "trigger") == "" ? json : pol_field(json, "trigger"));
    p.action          = PolicyAction::fromJSON(pol_field(json, "action") == "" ? json : pol_field(json, "action"));
    { auto v = pol_field(json, "enabled"); if (!v.empty()) p.enabled = (v == "true"); }
    { auto v = pol_field(json, "requiresUserApproval"); if (!v.empty()) p.requiresUserApproval = (v == "true"); }
    if (!pol_field(json, "priority").empty()) p.priority = std::stoi(pol_field(json, "priority"));
    if (!pol_field(json, "createdAt").empty()) p.createdAt = std::stoll(pol_field(json, "createdAt"));
    if (!pol_field(json, "modifiedAt").empty()) p.modifiedAt = std::stoll(pol_field(json, "modifiedAt"));
    p.createdBy       = pol_field(json, "createdBy");
    if (!pol_field(json, "appliedCount").empty()) p.appliedCount = std::stoi(pol_field(json, "appliedCount"));
    return p;
}

std::string PolicySuggestion::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"id\":\"" << pol_escape(id) << "\""
      << ",\"proposedPolicy\":" << proposedPolicy.toJSON()
      << ",\"rationale\":\"" << pol_escape(rationale) << "\""
      << ",\"estimatedImprovement\":" << estimatedImprovement
      << ",\"supportingEvents\":" << supportingEvents
      << ",\"state\":\"" << stateString() << "\""
      << ",\"generatedAt\":" << generatedAt
      << ",\"decidedAt\":" << decidedAt;
    j << ",\"affectedEventTypes\":[";
    for (size_t i = 0; i < affectedEventTypes.size(); ++i) { if (i) j << ","; j << "\"" << pol_escape(affectedEventTypes[i]) << "\""; }
    j << "],\"affectedAgentIds\":[";
    for (size_t i = 0; i < affectedAgentIds.size(); ++i) { if (i) j << ","; j << "\"" << pol_escape(affectedAgentIds[i]) << "\""; }
    j << "]}";
    return j.str();
}

PolicySuggestion PolicySuggestion::fromJSON(const std::string& json) {
    PolicySuggestion s;
    s.id            = pol_field(json, "id");
    s.rationale     = pol_field(json, "rationale");
    if (!pol_field(json, "estimatedImprovement").empty()) s.estimatedImprovement = std::stof(pol_field(json, "estimatedImprovement"));
    if (!pol_field(json, "supportingEvents").empty()) s.supportingEvents = std::stoi(pol_field(json, "supportingEvents"));
    if (!pol_field(json, "generatedAt").empty()) s.generatedAt = std::stoll(pol_field(json, "generatedAt"));
    if (!pol_field(json, "decidedAt").empty()) s.decidedAt = std::stoll(pol_field(json, "decidedAt"));
    { auto v = pol_field(json, "state"); if (v == "accepted") s.state = State::Accepted; else if (v == "rejected") s.state = State::Rejected; else if (v == "expired") s.state = State::Expired; }
    return s;
}

std::string PolicyHeuristic::toJSON() const {
    std::ostringstream j;
    j << "{"
      << "\"key\":\"" << pol_escape(key) << "\""
      << ",\"totalEvents\":" << totalEvents
      << ",\"successCount\":" << successCount
      << ",\"failCount\":" << failCount
      << ",\"successRate\":" << successRate
      << ",\"avgDurationMs\":" << avgDurationMs
      << ",\"p95DurationMs\":" << p95DurationMs
      << ",\"topFailureReasons\":[";
    for (size_t i = 0; i < topFailureReasons.size(); ++i) { if (i) j << ","; j << "\"" << pol_escape(topFailureReasons[i]) << "\""; }
    j << "]}";
    return j.str();
}

// ============================================================================
// PolicyEngine — construction
// ============================================================================

PolicyEngine::PolicyEngine(const std::string& storageDir) : m_storageDir(storageDir) {
    if (!m_storageDir.empty()) {
        try { fs::create_directories(m_storageDir); } catch (...) {}
    }
    load();
}

PolicyEngine::~PolicyEngine() {
    save();
}

// ============================================================================
// Helpers
// ============================================================================

std::string PolicyEngine::generateUUID() const {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch()).count();
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::ostringstream ss;
    ss << "pol-" << ms << "-" << std::hex << dis(gen);
    return ss.str();
}

int64_t PolicyEngine::nowMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string PolicyEngine::escapeJson(const std::string& s) const { return pol_escape(s); }
std::string PolicyEngine::unescapeJson(const std::string& s) const {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            switch (s[i + 1]) {
                case '\\': out += '\\'; i++; break;
                case '"':  out += '"';  i++; break;
                case 'n':  out += '\n'; i++; break;
                case 'r':  out += '\r'; i++; break;
                case 't':  out += '\t'; i++; break;
                default:   out += s[i]; break;
            }
        } else out += s[i];
    }
    return out;
}

std::string PolicyEngine::getPolicyFilePath() const {
    if (m_storageDir.empty()) return "";
    return (fs::path(m_storageDir) / "policies.json").string();
}
std::string PolicyEngine::getSuggestionsFilePath() const {
    if (m_storageDir.empty()) return "";
    return (fs::path(m_storageDir) / "policy_suggestions.json").string();
}

bool PolicyEngine::matchesTrigger(const PolicyTrigger& trigger,
                                  const std::string& eventType,
                                  const std::string& description,
                                  const std::string& toolName,
                                  const std::string& errorMessage) {
    if (!trigger.eventType.empty() && eventType != trigger.eventType) return false;
    if (!trigger.toolName.empty() && toolName != trigger.toolName) return false;
    if (!trigger.taskPattern.empty() && !pol_contains(description, trigger.taskPattern)) return false;
    if (!trigger.failureReason.empty() && !pol_contains(errorMessage, trigger.failureReason)) return false;
    return true;
}

PolicyAction PolicyEngine::mergePolicyActions(const std::vector<const AgentPolicy*>& policies) const {
    // Highest priority (lowest numeric) wins per field. -1/sentinel = no override.
    PolicyAction merged;
    auto byPriority = policies;
    std::sort(byPriority.begin(), byPriority.end(),
              [](const AgentPolicy* a, const AgentPolicy* b) { return a->priority < b->priority; });
    for (const auto* p : byPriority) {
        const PolicyAction& a = p->action;
        if (a.maxRetries != -1)          merged.maxRetries = a.maxRetries;
        if (a.retryDelayMs != -1)        merged.retryDelayMs = a.retryDelayMs;
        if (a.preferChainOverSwarm)      merged.preferChainOverSwarm = true;
        if (a.reduceParallelism != 0)    merged.reduceParallelism = a.reduceParallelism;
        if (a.timeoutOverrideMs != -1)   merged.timeoutOverrideMs = a.timeoutOverrideMs;
        if (a.confidenceThreshold != -1.0f) merged.confidenceThreshold = a.confidenceThreshold;
        if (a.addValidationStep)         merged.addValidationStep = true;
        if (!a.validationPrompt.empty()) merged.validationPrompt = a.validationPrompt;
        if (!a.customAction.empty())     merged.customAction = a.customAction;
    }
    return merged;
}

// ============================================================================
// Policy CRUD
// ============================================================================

std::string PolicyEngine::addPolicy(const AgentPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    AgentPolicy p = policy;
    if (p.id.empty()) p.id = generateUUID();
    if (p.createdAt == 0) p.createdAt = nowMs();
    p.modifiedAt = nowMs();
    m_policies.push_back(p);
    logDebug("[Policy] Added policy " + p.id + " (" + p.name + ")");
    save();
    return p.id;
}

bool PolicyEngine::updatePolicy(const std::string& policyId, const AgentPolicy& updated) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& p : m_policies) {
        if (p.id == policyId) {
            AgentPolicy np = updated;
            np.id = policyId;
            np.createdAt = p.createdAt;
            np.modifiedAt = nowMs();
            p = np;
            save();
            return true;
        }
    }
    return false;
}

bool PolicyEngine::removePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto before = m_policies.size();
    m_policies.erase(std::remove_if(m_policies.begin(), m_policies.end(),
                                    [&](const AgentPolicy& p) { return p.id == policyId; }),
                     m_policies.end());
    if (m_policies.size() != before) { save(); return true; }
    return false;
}

bool PolicyEngine::setEnabled(const std::string& policyId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& p : m_policies) {
        if (p.id == policyId) { p.enabled = enabled; p.modifiedAt = nowMs(); save(); return true; }
    }
    return false;
}

const AgentPolicy* PolicyEngine::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& p : m_policies) if (p.id == policyId) return &p;
    return nullptr;
}

std::vector<AgentPolicy> PolicyEngine::getAllPolicies(bool enabledOnly) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AgentPolicy> out;
    for (const auto& p : m_policies) if (!enabledOnly || p.enabled) out.push_back(p);
    return out;
}

size_t PolicyEngine::policyCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_policies.size();
}

// ============================================================================
// Evaluation — the seam referenced by SubAgentManager::spawnSubAgent
// ============================================================================

PolicyEvalResult PolicyEngine::evaluate(const std::string& eventType,
                                        const std::string& description,
                                        const std::string& toolName,
                                        const std::string& errorMessage) {
    m_evalCount.fetch_add(1);
    PolicyEvalResult result;

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& p : m_policies) {
        if (!p.enabled) continue;
        if (!matchesTrigger(p.trigger, eventType, description, toolName, errorMessage)) continue;
        result.matchedPolicies.push_back(&p);
    }

    if (result.matchedPolicies.empty()) {
        result.hasMatch = false;
        result.needsUserApproval = false;
        result.summary = "No policy matched";
        return result;
    }

    std::sort(result.matchedPolicies.begin(), result.matchedPolicies.end(),
              [](const AgentPolicy* a, const AgentPolicy* b) { return a->priority < b->priority; });

    result.hasMatch = true;
    result.mergedAction = mergePolicyActions(result.matchedPolicies);
    for (const auto* p : result.matchedPolicies) {
        if (p->requiresUserApproval) { result.needsUserApproval = true; break; }
        const_cast<AgentPolicy*>(p)->appliedCount++;
    }

    std::ostringstream ss;
    ss << result.matchedPolicies.size() << " policy(ies) matched";
    if (!result.matchedPolicies.empty()) ss << "; top=" << result.matchedPolicies.front()->name;
    result.summary = ss.str();

    m_matchCount.fetch_add(1);
    logDebug("[Policy] " + result.summary);
    return result;
}

// ============================================================================
// Heuristics (history-derived)
// ============================================================================

void PolicyEngine::computeHeuristics() {
    std::vector<PolicyHeuristic> heuristics;
    std::unordered_map<std::string, PolicyHeuristic> byKey;

    if (m_historyRecorder) {
        std::unordered_map<std::string, std::vector<int64_t>> durationsByKey;
        for (const auto& e : m_historyRecorder->allEvents()) {
            PolicyHeuristic& h = byKey[e.eventType];
            h.key = e.eventType;
            h.totalEvents++;
            if (e.success) h.successCount++; else h.failCount++;
            if (e.durationMs > 0) durationsByKey[e.eventType].push_back(e.durationMs);
            if (!e.success && !e.errorMessage.empty()) h.failureReasonCounts[e.errorMessage]++;
        }
        for (auto& [key, durs] : durationsByKey) {
            auto& h = byKey[key];
            if (durs.empty()) continue;
            std::sort(durs.begin(), durs.end());
            int64_t sum = 0; for (auto d : durs) sum += d;
            h.avgDurationMs = (float)sum / (float)durs.size();
            h.p95DurationMs = (float)durs[(size_t)((double)durs.size() * 0.95)];
        }
        for (auto& [key, h] : byKey) {
            h.successRate = h.totalEvents ? (float)h.successCount / (float)h.totalEvents : 0.0f;
            // Top failure reasons by count
            std::vector<std::pair<std::string, int>> reasons(h.failureReasonCounts.begin(), h.failureReasonCounts.end());
            std::sort(reasons.begin(), reasons.end(), [](auto& a, auto& b) { return a.second > b.second; });
            for (size_t i = 0; i < reasons.size() && i < 5; ++i) h.topFailureReasons.push_back(reasons[i].first);
            heuristics.push_back(h);
        }
    }

    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    m_heuristics = std::move(heuristics);
}

const PolicyHeuristic* PolicyEngine::getHeuristic(const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    for (const auto& h : m_heuristics) if (h.key == key) return &h;
    return nullptr;
}

std::vector<PolicyHeuristic> PolicyEngine::getAllHeuristics() const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    return m_heuristics;
}

std::string PolicyEngine::heuristicsSummaryJSON() const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    std::ostringstream j; j << "[";
    for (size_t i = 0; i < m_heuristics.size(); ++i) { if (i) j << ","; j << m_heuristics[i].toJSON(); }
    j << "]";
    return j.str();
}

// ============================================================================
// Suggestions
// ============================================================================

std::vector<PolicySuggestion> PolicyEngine::generateSuggestions() {
    std::vector<PolicySuggestion> out;
    computeHeuristics();

    std::vector<PolicyHeuristic> heur;
    { std::lock_guard<std::mutex> lock(m_heuristicsMutex); heur = m_heuristics; }

    for (const auto& h : heur) {
        // Suggest a retry policy when a category fails often.
        if (h.totalEvents >= 5 && h.successRate < 0.6f && !h.topFailureReasons.empty()) {
            PolicySuggestion s;
            s.id = generateUUID();
            s.generatedAt = nowMs();
            s.supportingEvents = h.failCount;
            s.estimatedImprovement = std::min(0.5f, (1.0f - h.successRate) * 0.5f);
            s.affectedEventTypes.push_back(h.key);
            s.proposedPolicy.id = generateUUID();
            s.proposedPolicy.name = "Retry-on-fail: " + h.key;
            s.proposedPolicy.description = "Increase retries for frequently-failing category '" + h.key + "'";
            s.proposedPolicy.trigger.eventType = h.key;
            s.proposedPolicy.trigger.failureReason = h.topFailureReasons.front();
            s.proposedPolicy.trigger.minOccurrences = 3;
            s.proposedPolicy.action.maxRetries = 5;
            s.proposedPolicy.action.retryDelayMs = 1000;
            s.proposedPolicy.createdBy = "system";
            s.rationale = "Observed success rate " + std::to_string(h.successRate) +
                          " over " + std::to_string(h.totalEvents) + " events; suggest more retries.";
            out.push_back(s);
        }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : out) m_suggestions.push_back(s);
    return out;
}

bool PolicyEngine::acceptSuggestion(const std::string& suggestionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_suggestions) {
        if (s.id == suggestionId && s.state == PolicySuggestion::State::Pending) {
            s.state = PolicySuggestion::State::Accepted;
            s.decidedAt = nowMs();
            // Convert to an active policy (disabled until the user enables it).
            AgentPolicy p = s.proposedPolicy;
            p.enabled = false;
            p.requiresUserApproval = false;
            p.createdBy = "import";
            if (p.id.empty()) p.id = generateUUID();
            p.createdAt = nowMs();
            p.modifiedAt = nowMs();
            m_policies.push_back(p);
            save();
            return true;
        }
    }
    return false;
}

bool PolicyEngine::rejectSuggestion(const std::string& suggestionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_suggestions) {
        if (s.id == suggestionId && s.state == PolicySuggestion::State::Pending) {
            s.state = PolicySuggestion::State::Rejected;
            s.decidedAt = nowMs();
            return true;
        }
    }
    return false;
}

std::vector<PolicySuggestion> PolicyEngine::getPendingSuggestions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<PolicySuggestion> out;
    for (const auto& s : m_suggestions) if (s.state == PolicySuggestion::State::Pending) out.push_back(s);
    return out;
}

std::vector<PolicySuggestion> PolicyEngine::getAllSuggestions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_suggestions;
}

// ============================================================================
// Export / Import / Persistence
// ============================================================================

std::string PolicyEngine::exportPolicies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream j; j << "[";
    bool first = true;
    for (const auto& p : m_policies) {
        if (!p.enabled) continue;
        if (!first) j << ",";
        j << p.toJSON();
        first = false;
    }
    j << "]";
    return j.str();
}

int PolicyEngine::importPolicies(const std::string& json) {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Parse a JSON array of policy objects by brace-matching (self-contained).
    int imported = 0;
    size_t i = 0;
    while (i < json.size()) {
        if (json[i] == '{') {
            int depth = 0; size_t start = i;
            for (; i < json.size(); ++i) {
                if (json[i] == '{') depth++;
                else if (json[i] == '}') { depth--; if (depth == 0) { ++i; break; } }
            }
            std::string obj = json.substr(start, i - start);
            try {
                AgentPolicy p = AgentPolicy::fromJSON(obj);
                if (!p.name.empty() || !p.id.empty()) {
                    p.createdBy = "import";
                    p.enabled = false; // imported policies stay opt-in
                    m_policies.push_back(p);
                    imported++;
                }
            } catch (...) {}
        } else ++i;
    }
    if (imported) save();
    return imported;
}

bool PolicyEngine::exportToFile(const std::string& filePath) const {
    try {
        std::ofstream f(filePath, std::ios::trunc);
        if (!f.is_open()) return false;
        f << exportPolicies();
        return true;
    } catch (...) { return false; }
}

int PolicyEngine::importFromFile(const std::string& filePath) {
    try {
        std::ifstream f(filePath);
        if (!f.is_open()) return 0;
        std::ostringstream ss; ss << f.rdbuf();
        return importPolicies(ss.str());
    } catch (...) { return 0; }
}

void PolicyEngine::save() {
    std::string path = getPolicyFilePath();
    if (path.empty()) return;
    try {
        std::ofstream f(path, std::ios::trunc);
        if (!f.is_open()) return;
        f << exportPolicies();
    } catch (...) {}

    std::string spath = getSuggestionsFilePath();
    if (spath.empty()) return;
    try {
        std::ofstream sf(spath, std::ios::trunc);
        if (!sf.is_open()) return;
        sf << "[";
        for (size_t i = 0; i < m_suggestions.size(); ++i) { if (i) sf << ","; sf << m_suggestions[i].toJSON(); }
        sf << "]";
    } catch (...) {}
}

void PolicyEngine::load() {
    std::string path = getPolicyFilePath();
    if (path.empty() || !fs::exists(path)) return;
    importFromFile(path);
}

// ============================================================================
// Statistics
// ============================================================================

std::string PolicyEngine::getStatsSummary() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream j;
    j << "{\"policyCount\":" << m_policies.size()
      << ",\"suggestionCount\":" << m_suggestions.size()
      << ",\"evalCount\":" << m_evalCount.load()
      << ",\"matchCount\":" << m_matchCount.load()
      << "}";
    return j.str();
}
