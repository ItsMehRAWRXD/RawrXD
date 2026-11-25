// =============================================================================
// agent_policy.cpp — PolicyEngine implementation (fail-closed evaluation).
// =============================================================================
#include "agent_policy.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <sstream>

#include "agent_history.h"

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

std::string JsonUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) { out += s[i]; continue; }
        const char c = s[++i];
        switch (c) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            default: out += c; break;
        }
    }
    return out;
}

std::string Field(const std::string& j, const std::string& key) {
    const std::string pat = "\"" + key + "\":\"";
    const size_t p = j.find(pat);
    if (p == std::string::npos) return {};
    const size_t s = p + pat.size();
    size_t e = s;
    while (e < j.size() && j[e] != '"') ++e;
    return JsonUnescape(j.substr(s, e - s));
}

int FieldInt(const std::string& j, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    const size_t p = j.find(pat);
    if (p == std::string::npos) return 0;
    return (int)std::strtol(j.c_str() + p + pat.size(), nullptr, 10);
}

bool FieldBool(const std::string& j, const std::string& key) {
    return j.find("\"" + key + "\":true") != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// JSON (de)serialization for the policy structs
// ---------------------------------------------------------------------------
std::string PolicyTrigger::toJSON() const {
    return "{\"eventType\":\"" + JsonEscape(eventType) +
           "\",\"failureReason\":\"" + JsonEscape(failureReason) +
           "\",\"taskPattern\":\"" + JsonEscape(taskPattern) +
           "\",\"toolName\":\"" + JsonEscape(toolName) + "\"}";
}
PolicyTrigger PolicyTrigger::fromJSON(const std::string& j) {
    PolicyTrigger t;
    t.eventType = Field(j, "eventType");
    t.failureReason = Field(j, "failureReason");
    t.taskPattern = Field(j, "taskPattern");
    t.toolName = Field(j, "toolName");
    return t;
}

std::string PolicyAction::toJSON() const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "{\"maxRetries\":%d,\"retryDelayMs\":%d,"
                  "\"preferChainOverSwarm\":%s,\"reduceParallelism\":%d,"
                  "\"timeoutOverrideMs\":%d,\"confidenceThreshold\":%.2f,"
                  "\"addValidationStep\":%s,\"validationPrompt\":\"%s\","
                  "\"customAction\":\"%s\"}",
                  maxRetries, retryDelayMs,
                  preferChainOverSwarm ? "true" : "false", reduceParallelism,
                  timeoutOverrideMs, confidenceThreshold,
                  addValidationStep ? "true" : "false",
                  JsonEscape(validationPrompt).c_str(),
                  JsonEscape(customAction).c_str());
    return buf;
}
PolicyAction PolicyAction::fromJSON(const std::string& j) {
    PolicyAction a;
    a.maxRetries = FieldInt(j, "maxRetries");
    a.retryDelayMs = FieldInt(j, "retryDelayMs");
    a.preferChainOverSwarm = FieldBool(j, "preferChainOverSwarm");
    a.reduceParallelism = FieldInt(j, "reduceParallelism");
    a.timeoutOverrideMs = FieldInt(j, "timeoutOverrideMs");
    a.confidenceThreshold = -1.0f;
    a.addValidationStep = FieldBool(j, "addValidationStep");
    a.validationPrompt = Field(j, "validationPrompt");
    a.customAction = Field(j, "customAction");
    return a;
}

std::string AgentPolicy::toJSON() const {
    return "{\"id\":\"" + JsonEscape(id) + "\",\"name\":\"" +
           JsonEscape(name) + "\",\"description\":\"" +
           JsonEscape(description) + "\",\"version\":" +
           std::to_string(version) + ",\"trigger\":" + trigger.toJSON() +
           ",\"action\":" + action.toJSON() + ",\"enabled\":" +
           (enabled ? "true" : "false") + ",\"requiresUserApproval\":" +
           (requiresUserApproval ? "true" : "false") +
           ",\"priority\":" + std::to_string(priority) + "}";
}
AgentPolicy AgentPolicy::fromJSON(const std::string& j) {
    AgentPolicy p;
    p.id = Field(j, "id");
    p.name = Field(j, "name");
    p.description = Field(j, "description");
    p.version = FieldInt(j, "version");
    p.trigger = PolicyTrigger::fromJSON(j);
    p.action = PolicyAction::fromJSON(j);
    p.enabled = FieldBool(j, "enabled");
    p.requiresUserApproval = FieldBool(j, "requiresUserApproval");
    p.priority = FieldInt(j, "priority");
    return p;
}

std::string PolicySuggestion::toJSON() const {
    return "{\"id\":\"" + JsonEscape(id) + "\",\"policy\":" +
           proposedPolicy.toJSON() + ",\"rationale\":\"" +
           JsonEscape(rationale) + "\",\"state\":\"" + stateString() +
           "\"}";
}
PolicySuggestion PolicySuggestion::fromJSON(const std::string& j) {
    PolicySuggestion s;
    s.id = Field(j, "id");
    s.rationale = Field(j, "rationale");
    const std::string st = Field(j, "state");
    if (st == "accepted") s.state = State::Accepted;
    else if (st == "rejected") s.state = State::Rejected;
    else if (st == "expired") s.state = State::Expired;
    return s;
}

std::string PolicyHeuristic::toJSON() const {
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "{\"key\":\"%s\",\"totalEvents\":%d,\"successCount\":%d,"
                  "\"failCount\":%d,\"successRate\":%.3f}",
                  JsonEscape(key).c_str(), totalEvents, successCount,
                  failCount, successRate);
    return buf;
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------
PolicyEngine::PolicyEngine(const std::string& storageDir)
    : m_storageDir(storageDir) {
    load();
}

PolicyEngine::~PolicyEngine() { save(); }

std::string PolicyEngine::generateUUID() const {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    char buf[24];
    std::snprintf(buf, sizeof(buf), "pol_%016llx",
                  (unsigned long long)gen());
    return buf;
}

int64_t PolicyEngine::nowMs() const {
    return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string PolicyEngine::escapeJson(const std::string& s) const {
    return JsonEscape(s);
}
std::string PolicyEngine::unescapeJson(const std::string& s) const {
    return JsonUnescape(s);
}

std::string PolicyEngine::getPolicyFilePath() const {
    return m_storageDir.empty() ? std::string() : m_storageDir + "/policies.json";
}
std::string PolicyEngine::getSuggestionsFilePath() const {
    return m_storageDir.empty() ? std::string()
                                : m_storageDir + "/suggestions.json";
}

std::string PolicyEngine::addPolicy(const AgentPolicy& policy) {
    std::lock_guard<std::mutex> lock(m_mutex);
    AgentPolicy p = policy;
    if (p.id.empty()) p.id = generateUUID();
    p.createdAt = nowMs();
    p.modifiedAt = p.createdAt;
    m_policies.push_back(p);
    logInfo("policy added " + p.id);
    return p.id;
}

bool PolicyEngine::updatePolicy(const std::string& policyId,
                                const AgentPolicy& updated) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& p : m_policies) {
        if (p.id == policyId) {
            p = updated;
            p.id = policyId;
            p.modifiedAt = nowMs();
            return true;
        }
    }
    return false;
}

bool PolicyEngine::removePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto before = m_policies.size();
    m_policies.erase(std::remove_if(m_policies.begin(), m_policies.end(),
                                    [&policyId](const AgentPolicy& p) {
                                        return p.id == policyId;
                                    }),
                     m_policies.end());
    return m_policies.size() != before;
}

bool PolicyEngine::setEnabled(const std::string& policyId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& p : m_policies) {
        if (p.id == policyId) {
            p.enabled = enabled;
            p.modifiedAt = nowMs();
            return true;
        }
    }
    return false;
}

const AgentPolicy* PolicyEngine::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& p : m_policies)
        if (p.id == policyId) return &p;
    return nullptr;
}

std::vector<AgentPolicy> PolicyEngine::getAllPolicies(bool enabledOnly) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AgentPolicy> out;
    for (const auto& p : m_policies)
        if (!enabledOnly || p.enabled) out.push_back(p);
    return out;
}

size_t PolicyEngine::policyCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_policies.size();
}

bool PolicyEngine::matchesTrigger(const PolicyTrigger& trigger,
                                  const std::string& eventType,
                                  const std::string& description,
                                  const std::string& toolName,
                                  const std::string& errorMessage) {
    if (!trigger.eventType.empty() && trigger.eventType != eventType)
        return false;
    if (!trigger.failureReason.empty() &&
        errorMessage.find(trigger.failureReason) == std::string::npos)
        return false;
    if (!trigger.taskPattern.empty() &&
        description.find(trigger.taskPattern) == std::string::npos)
        return false;
    if (!trigger.toolName.empty() && trigger.toolName != toolName)
        return false;
    return true;
}

PolicyAction PolicyEngine::mergePolicyActions(
    const std::vector<const AgentPolicy*>& policies) const {
    PolicyAction merged;
    for (const auto* p : policies) {
        const auto& a = p->action;
        if (a.maxRetries >= 0) merged.maxRetries = a.maxRetries;
        if (a.retryDelayMs >= 0) merged.retryDelayMs = a.retryDelayMs;
        if (a.preferChainOverSwarm) merged.preferChainOverSwarm = true;
        if (a.reduceParallelism > 0)
            merged.reduceParallelism = a.reduceParallelism;
        if (a.timeoutOverrideMs >= 0)
            merged.timeoutOverrideMs = a.timeoutOverrideMs;
        if (a.confidenceThreshold >= 0.0f)
            merged.confidenceThreshold = a.confidenceThreshold;
        if (a.addValidationStep) {
            merged.addValidationStep = true;
            merged.validationPrompt = a.validationPrompt;
        }
        if (!a.customAction.empty()) merged.customAction = a.customAction;
    }
    return merged;
}

PolicyEvalResult PolicyEngine::evaluate(const std::string& eventType,
                                        const std::string& description,
                                        const std::string& toolName,
                                        const std::string& errorMessage) {
    PolicyEvalResult r;
    m_evalCount++;
    std::vector<const AgentPolicy*> matched;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& p : m_policies) {
            if (!p.enabled) continue;
            if (matchesTrigger(p.trigger, eventType, description, toolName,
                               errorMessage))
                matched.push_back(&p);
        }
        std::sort(matched.begin(), matched.end(),
                  [](const AgentPolicy* a, const AgentPolicy* b) {
                      return a->priority < b->priority;
                  });
    }
    if (matched.empty()) {
        // Fail-closed default: no match, no action.
        r.summary = "no policy matched";
        return r;
    }
    r.hasMatch = true;
    r.matchedPolicies = matched;
    r.mergedAction = mergePolicyActions(matched);
    for (const auto* p : matched)
        r.needsUserApproval = r.needsUserApproval || p->requiresUserApproval;
    m_matchCount++;
    r.summary = std::to_string(matched.size()) + " policy(ies) matched";
    return r;
}

void PolicyEngine::computeHeuristics() {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    m_heuristics.clear();
    if (!m_historyRecorder) return;
    const auto events = m_historyRecorder->allEvents();
    std::map<std::string, std::pair<int, int>> stats;  // key -> (ok, total)
    std::map<std::string, int> failReasons;
    for (const auto& e : events) {
        const std::string key = e.eventType;
        auto& s = stats[key];
        s.second++;
        if (e.success) s.first++;
        else failReasons[e.errorMessage]++;
    }
    for (const auto& [key, s] : stats) {
        PolicyHeuristic h;
        h.key = key;
        h.totalEvents = s.second;
        h.successCount = s.first;
        h.failCount = s.second - s.first;
        h.successRate = s.second > 0
            ? (float)h.successCount / (float)s.second : 0.0f;
        m_heuristics.push_back(h);
    }
}

const PolicyHeuristic* PolicyEngine::getHeuristic(
    const std::string& key) const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    for (const auto& h : m_heuristics)
        if (h.key == key) return &h;
    return nullptr;
}

std::vector<PolicyHeuristic> PolicyEngine::getAllHeuristics() const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    return m_heuristics;
}

std::string PolicyEngine::heuristicsSummaryJSON() const {
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    std::string out = "[";
    for (size_t i = 0; i < m_heuristics.size(); ++i) {
        if (i) out += ",";
        out += m_heuristics[i].toJSON();
    }
    out += "]";
    return out;
}

std::vector<PolicySuggestion> PolicyEngine::generateSuggestions() {
    computeHeuristics();
    std::vector<PolicySuggestion> out;
    std::lock_guard<std::mutex> lock(m_heuristicsMutex);
    for (const auto& h : m_heuristics) {
        if (h.totalEvents < 5 || h.successRate > 0.5f) continue;
        PolicySuggestion s;
        s.id = generateUUID();
        s.proposedPolicy.id = generateUUID();
        s.proposedPolicy.name = "retry policy for " + h.key;
        s.proposedPolicy.description =
            "Auto-generated: low success rate";
        s.proposedPolicy.trigger.eventType = h.key;
        s.proposedPolicy.action.maxRetries = 2;
        s.rationale = h.key + " success rate " +
                      std::to_string((int)(h.successRate * 100)) +
                      "% over " + std::to_string(h.totalEvents) + " events";
        s.supportingEvents = h.totalEvents;
        s.generatedAt = nowMs();
        out.push_back(s);
    }
    std::lock_guard<std::mutex> slock(m_mutex);
    m_suggestions.insert(m_suggestions.end(), out.begin(), out.end());
    return out;
}

bool PolicyEngine::acceptSuggestion(const std::string& suggestionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_suggestions) {
        if (s.id == suggestionId && s.state == PolicySuggestion::State::Pending) {
            s.state = PolicySuggestion::State::Accepted;
            s.decidedAt = nowMs();
            AgentPolicy p = s.proposedPolicy;
            p.createdAt = nowMs();
            p.createdBy = "user";
            m_policies.push_back(p);
            return true;
        }
    }
    return false;
}

bool PolicyEngine::rejectSuggestion(const std::string& suggestionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& s : m_suggestions) {
        if (s.id == suggestionId &&
            s.state == PolicySuggestion::State::Pending) {
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
    for (const auto& s : m_suggestions)
        if (s.state == PolicySuggestion::State::Pending) out.push_back(s);
    return out;
}

std::vector<PolicySuggestion> PolicyEngine::getAllSuggestions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_suggestions;
}

std::string PolicyEngine::exportPolicies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string out = "[";
    bool first = true;
    for (const auto& p : m_policies) {
        if (!p.enabled) continue;
        if (!first) out += ",";
        first = false;
        out += p.toJSON();
    }
    out += "]";
    return out;
}

int PolicyEngine::importPolicies(const std::string& json) {
    int count = 0;
    size_t p = 0;
    while ((p = json.find("{\"id\"", p)) != std::string::npos) {
        const size_t e = json.find("}", p);
        if (e == std::string::npos) break;
        // Extract the full object (nested braces in trigger/action).
        int depth = 0;
        size_t end = p;
        for (; end < json.size(); ++end) {
            if (json[end] == '{') ++depth;
            else if (json[end] == '}') {
                if (--depth == 0) break;
            }
        }
        const std::string obj = json.substr(p, end - p + 1);
        addPolicy(AgentPolicy::fromJSON(obj));
        ++count;
        p = end + 1;
    }
    return count;
}

bool PolicyEngine::exportToFile(const std::string& filePath) const {
    std::ofstream out(filePath);
    if (!out) return false;
    out << exportPolicies();
    return true;
}

int PolicyEngine::importFromFile(const std::string& filePath) {
    std::ifstream in(filePath);
    if (!in) return 0;
    std::stringstream ss;
    ss << in.rdbuf();
    return importPolicies(ss.str());
}

void PolicyEngine::save() {
    const std::string path = getPolicyFilePath();
    if (path.empty()) return;
    std::string json;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Build inline (exportPolicies() re-locks m_mutex; do not call it
        // while holding the lock).
        json = "[";
        bool first = true;
        for (const auto& p : m_policies) {
            if (!p.enabled) continue;
            if (!first) json += ",";
            first = false;
            json += p.toJSON();
        }
        json += "]";
    }
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path());
    std::ofstream out(path);
    if (!out) return;
    out << json;
}

void PolicyEngine::load() {
    const std::string path = getPolicyFilePath();
    if (path.empty()) return;
    std::ifstream in(path);
    if (!in) return;
    std::stringstream ss;
    ss << in.rdbuf();
    importPolicies(ss.str());
}

std::string PolicyEngine::getStatsSummary() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "{\"policies\":%zu,\"evaluations\":%d,\"matches\":%d}",
                  m_policies.size(), m_evalCount.load(),
                  m_matchCount.load());
    return buf;
}