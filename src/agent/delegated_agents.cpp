// ============================================================================
// File: src/agent/delegated_agents.cpp
//
// Implementation of Delegated Agent Lifecycle Management
// ============================================================================

#include "delegated_agents.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Delegation {

// ---- capability parsing from task metadata (defined before first use) ----
static bool taskHasCapabilityRequirement(const DelegatedTask& task) {
    return task.metadata.find("required_capabilities") != task.metadata.end();
}

static std::vector<AgentCapability> requiredCapabilitiesOf(const DelegatedTask& task) {
    std::vector<AgentCapability> caps;
    auto it = task.metadata.find("required_capabilities");
    if (it == task.metadata.end()) return caps;

    std::stringstream ss(it->second);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        while (!tok.empty() && std::isspace(static_cast<unsigned char>(tok.back()))) tok.pop_back();
        size_t b = 0;
        while (b < tok.size() && std::isspace(static_cast<unsigned char>(tok[b]))) ++b;
        tok = tok.substr(b);
        if (tok == "code_edit") caps.push_back(AgentCapability::CodeEdit);
        else if (tok == "build_and_test") caps.push_back(AgentCapability::BuildAndTest);
        else if (tok == "research") caps.push_back(AgentCapability::Research);
        else if (tok == "git") caps.push_back(AgentCapability::Git);
        else if (tok == "planning") caps.push_back(AgentCapability::Planning);
        else if (tok == "verification") caps.push_back(AgentCapability::Verification);
        else if (tok == "docs") caps.push_back(AgentCapability::Docs);
    }
    return caps;
}

// ============================================================================
// DelegatedResult
// ============================================================================

std::string DelegatedResult::toJSON() const {
    std::ostringstream oss;
    auto escape = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        return out;
    };

    oss << "{"
        << "\"taskId\":\"" << escape(taskId) << "\","
        << "\"agentId\":\"" << escape(agentId) << "\","
        << "\"success\":" << (success ? "true" : "false") << ","
        << "\"output\":\"" << escape(output) << "\","
        << "\"error\":\"" << escape(errorMessage) << "\","
        << "\"tokensUsed\":" << usage.tokensUsed << ","
        << "\"wallTimeMs\":" << usage.wallTimeMs << ","
        << "\"cpuTimeMs\":" << usage.cpuTimeMs << ","
        << "\"toolCalls\":" << usage.toolCalls << ","
        << "\"fileEdits\":" << usage.fileEdits << ","
        << "\"costUsd\":" << usage.costUsd << ","
        << "\"startedAt\":" << startedAt << ","
        << "\"completedAt\":" << completedAt << ","
        << "\"elapsedMs\":" << elapsedMs();
    oss << ",\"artifacts\":[";
    for (size_t i = 0; i < artifacts.size(); ++i) {
        if (i) oss << ",";
        oss << "\"" << escape(artifacts[i]) << "\"";
    }
    oss << "]}";
    return oss.str();
}

// ============================================================================
// DelegationManager
// ============================================================================

DelegationManager::DelegationManager(const Config& config)
    : m_config(config) {
    if (!m_config.defaultLimits.isValid()) {
        m_config.defaultLimits = ResourceLimits{};
    }
    if (m_config.maxDelegationDepth < 1) m_config.maxDelegationDepth = 1;
    if (m_config.maxConcurrentAgents < 1) m_config.maxConcurrentAgents = 1;

    // NO default success. If no real work function is wired, the task must
    // FAIL loudly rather than return a fabricated "Completed: ..." string.
    // Silently claiming success when no engine ran is a mocked result, and this
    // project forbids that.
    m_workFn = nullptr;

    m_running.store(true);
    m_scheduler = std::thread([this]() { schedulerLoop(); });
}

DelegationManager::~DelegationManager() {
    m_shutdown.store(true);
    m_queueCv.notify_all();
    m_idleCv.notify_all();
    if (m_scheduler.joinable()) m_scheduler.join();
}

void DelegationManager::setConfig(const Config& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
    if (m_config.maxConcurrentAgents < 1) m_config.maxConcurrentAgents = 1;
    if (m_config.maxDelegationDepth < 1) m_config.maxDelegationDepth = 1;
}

DelegationManager::Config DelegationManager::getConfig() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

void DelegationManager::setAgentWorkFn(AgentWorkFn fn) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_workFn = std::move(fn);
}

int64_t DelegationManager::nowMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string DelegationManager::makeId(const char* prefix) const {
    static std::atomic<uint64_t> counter{0};
    uint64_t c = counter.fetch_add(1);
    std::ostringstream oss;
    oss << prefix << "-" << std::hex << nowMs() << "-" << c;
    return oss.str();
}

void DelegationManager::setAgentState(const std::shared_ptr<DelegatedAgent>& agent,
                                      AgentState newState) {
    if (!agent) return;
    AgentState old = agent->state;
    if (old == newState) return;
    agent->state = newState;
    if (newState == AgentState::Completed || newState == AgentState::Failed ||
        newState == AgentState::Cancelled || newState == AgentState::TimedOut) {
        agent->finishedAt = nowMs();
    }
    if (m_stateCb) {
        m_stateCb(agent->agentId, newState);
    }

    std::ostringstream log;
    log << "{\"event\":\"state_change\",\"agent\":\"" << agent->agentId
        << "\",\"from\":\"" << stateName(old) << "\",\"to\":\"" << stateName(newState)
        << "\",\"ts\":" << nowMs() << "}";
    auditLog(log.str());
}

void DelegationManager::auditLog(const std::string& json) const {
    if (m_config.logPath.empty()) return;
    std::ofstream f(m_config.logPath, std::ios::app);
    if (f.is_open()) f << json << "\n";
}

bool DelegationManager::wouldExceedDepth(const std::string& parentAgentId) const {
    if (parentAgentId.empty()) return false;
    auto it = m_agents.find(parentAgentId);
    if (it == m_agents.end()) return false;
    return it->second->depth + 1 >= m_config.maxDelegationDepth;
}

std::string DelegationManager::createAgent(const std::string& label,
                                            const std::vector<AgentCapability>& capabilities,
                                            const ResourceLimits& limits,
                                            const std::string& parentAgentId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return createAgentLocked(label, capabilities, limits, parentAgentId);
}

// Caller MUST hold m_mutex.
std::string DelegationManager::createAgentLocked(const std::string& label,
                                                 const std::vector<AgentCapability>& capabilities,
                                                 const ResourceLimits& limits,
                                                 const std::string& parentAgentId) {

    if (wouldExceedDepth(parentAgentId)) {
        auditLog("{\"event\":\"delegation_refused\",\"reason\":\"max_delegation_depth\",\"parent\":\"" +
                 parentAgentId + "\"}");
        return "";
    }

    auto agent = std::make_shared<DelegatedAgent>(makeId("agent"), label);
    agent->capabilities = capabilities;
    agent->limits = limits.isValid() ? limits : m_config.defaultLimits;
    agent->parentAgentId = parentAgentId;
    agent->depth = parentAgentId.empty() ? 0 : [&] {
        auto it = m_agents.find(parentAgentId);
        return it != m_agents.end() ? it->second->depth + 1 : 1;
    }();
    agent->cancelToken = std::make_shared<std::atomic<bool>>(false);

    std::string id = agent->agentId;
    m_agents[id] = agent;
    m_totalCreated++;

    // Account the child against the parent's sub-agent quota.
    if (!parentAgentId.empty()) {
        auto pit = m_agents.find(parentAgentId);
        if (pit != m_agents.end()) {
            pit->second->usage.subAgents++;
            if (m_config.enforceQuotas &&
                pit->second->usage.subAgents > pit->second->limits.maxSubAgents) {
                // Over quota: remove the newly created agent and refuse.
                m_agents.erase(id);
                pit->second->usage.subAgents--;
                auditLog("{\"event\":\"delegation_refused\",\"reason\":\"parent_subagent_quota\",\"parent\":\"" +
                         parentAgentId + "\"}");
                return "";
            }
        }
    }

    auditLog("{\"event\":\"agent_created\",\"agent\":\"" + id + "\",\"label\":\"" + label +
             "\",\"parent\":\"" + parentAgentId + "\"}");
    return id;
}

bool DelegationManager::removeAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_agents.find(agentId);
    if (it == m_agents.end()) return false;

    // Remove children first (depth-first) to avoid orphans.
    std::vector<std::string> toRemove;
    std::function<void(const std::string&)> collect = [&](const std::string& id) {
        for (const auto& pair : m_agents) {
            if (pair.second->parentAgentId == id) collect(pair.first);
        }
        toRemove.push_back(id);
    };
    collect(agentId);

    for (const auto& id : toRemove) {
        auto a = m_agents.find(id);
        if (a != m_agents.end()) {
            if (a->second->cancelToken) a->second->cancelToken->store(true);
            m_agents.erase(a);
        }
    }
    return true;
}

void DelegationManager::removeAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& pair : m_agents) {
        if (pair.second->cancelToken) pair.second->cancelToken->store(true);
    }
    m_agents.clear();
    m_tasks.clear();
    std::queue<std::string>().swap(m_readyQueue);
}

DelegatedAgent* DelegationManager::getAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_agents.find(agentId);
    return it != m_agents.end() ? it->second.get() : nullptr;
}

std::vector<DelegatedAgent> DelegationManager::getAllAgents() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<DelegatedAgent> out;
    out.reserve(m_agents.size());
    for (const auto& pair : m_agents) out.push_back(*pair.second);
    return out;
}

std::string DelegationManager::delegate(const DelegatedTask& task, const std::string& toAgentId) {
    std::shared_ptr<DelegatedAgent> agent;
    std::shared_ptr<PendingTask> pending = std::make_shared<PendingTask>();
    pending->task = task;
    pending->resultId = task.taskId.empty() ? makeId("task") : task.taskId;
    pending->task.taskId = pending->resultId;
    pending->task.createdAt = pending->task.createdAt ? pending->task.createdAt : nowMs();

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Resolve target agent
        if (!task.parentAgentId.empty() && toAgentId.empty()) {
            auto pit = m_agents.find(task.parentAgentId);
            if (pit != m_agents.end()) {
                if (m_config.enforceQuotas && pit->second->state == AgentState::Running) {
                    // Parent is busy; still queue (the scheduler serializes)
                }
            }
        }

        std::string targetId = toAgentId;
        if (targetId.empty()) {
            // Pick an idle agent that satisfies the required capabilities.
            auto requiredCaps = requiredCapabilitiesOf(task);
            bool hasRequirement = taskHasCapabilityRequirement(task);

            DelegatedAgent* best = nullptr;
            for (auto& pair : m_agents) {
                auto& candidate = pair.second;
                // Only agents that are idle and non-terminal can take new work.
                if (candidate->isTerminal()) continue;
                if (candidate->state != AgentState::Created) continue;

                if (hasRequirement) {
                    bool all = true;
                    for (auto cap : requiredCaps) {
                        if (!candidate->hasCapability(cap)) { all = false; break; }
                    }
                    if (!all) continue;
                }
                if (!best || candidate->tasksCompleted < best->tasksCompleted) {
                    best = candidate.get();
                }
            }
            if (best) targetId = best->agentId;
        }

        if (targetId.empty()) {
            // No reusable agent: create one inheriting parent context.
            std::vector<AgentCapability> caps = requiredCapabilitiesOf(task);
            std::string label = task.title.empty() ? "agent" : task.title;
            if (label.size() > 32) label.resize(32);
            ResourceLimits limits = task.limits.isValid() ? task.limits : m_config.defaultLimits;

            std::string newId = createAgentLocked(label, caps, limits, task.parentAgentId);
            if (newId.empty()) {
                return "";   // refused (depth/quota)
            }
            targetId = newId;
        }

        agent = m_agents[targetId];
        agent->hasTask = true;
        agent->currentTask = task;

        // Verify capability satisfaction
        if (m_config.enforceQuotas) {
            auto requiredCaps = requiredCapabilitiesOf(task);
            for (auto cap : requiredCaps) {
                if (!agent->hasCapability(cap)) {
                    agent->hasTask = false;
                    auditLog("{\"event\":\"delegation_refused\",\"reason\":\"missing_capability\",\"agent\":\"" +
                             targetId + "\"}");
                    return "";
                }
            }
        }

        pending->agentId = targetId;
        m_tasks[pending->resultId] = pending;
        m_readyQueue.push(targetId);
    }

    m_queueCv.notify_one();

    auditLog("{\"event\":\"delegated\",\"task\":\"" + pending->resultId + "\",\"agent\":\"" +
             (agent ? agent->agentId : std::string()) + "\"}");

    if (m_config.autoStart) {
        m_queueCv.notify_one();
    }
    return pending->resultId;
}

std::string DelegationManager::delegateToNew(const DelegatedTask& task,
                                            const std::string& label,
                                            const std::vector<AgentCapability>& capabilities,
                                            const ResourceLimits& limits) {
    std::string id;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        id = createAgentLocked(label, capabilities, limits, task.parentAgentId);
    }
    if (id.empty()) return "";
    return delegate(task, id);
}

void DelegationManager::schedulerLoop() {
    while (true) {
        std::string agentId;
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait(lock, [this]() { return m_shutdown.load() || !m_readyQueue.empty(); });
            if (m_shutdown.load() && m_readyQueue.empty()) return;

            // Respect concurrency limit
            if (m_activeAgents.load() >= m_config.maxConcurrentAgents) {
                // Wait for a slot
                m_idleCv.wait_for(lock, std::chrono::milliseconds(50));
                continue;
            }
            agentId = m_readyQueue.front();
            m_readyQueue.pop();
        }
        if (agentId.empty()) continue;

        // The ActiveAgentGuard inside runAgent() owns the matching decrement.
        m_activeAgents++;
        std::thread([this, agentId]() {
            runAgent(agentId);
        }).detach();
    }
}

// RAII guard: guarantees the active-agent counter is decremented and waiters
// are notified even when runAgent() returns early (missing agent, no pending
// task, or an exception). Without this the counter underflows to negative.
class ActiveAgentGuard {
public:
    explicit ActiveAgentGuard(std::atomic<int>& counter, std::condition_variable& cv)
        : m_counter(counter), m_cv(cv) {}
    ~ActiveAgentGuard() {
        m_counter--;
        m_cv.notify_all();
    }
    ActiveAgentGuard(const ActiveAgentGuard&) = delete;
    ActiveAgentGuard& operator=(const ActiveAgentGuard&) = delete;
private:
    std::atomic<int>& m_counter;
    std::condition_variable& m_cv;
};

void DelegationManager::runAgent(const std::string& agentId) {
    // Any early return below still decrements the counter via the guard.
    ActiveAgentGuard activeGuard(m_activeAgents, m_idleCv);

    std::shared_ptr<DelegatedAgent> agent;
    std::shared_ptr<PendingTask> task;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_agents.find(agentId);
        if (it == m_agents.end()) return;
        agent = it->second;
        if (!agent->hasTask) return;
        for (auto& pair : m_tasks) {
            if (pair.second->agentId == agentId && !pair.second->done) { task = pair.second; break; }
        }
    }
    if (!task) return;

    setAgentState(agent, AgentState::Running);
    agent->startedAt = nowMs();
    agent->usage.wallTimeMs = 0;   // will be finalized
    agent->usage.cpuTimeMs = 0;
    int64_t startTime = nowMs();

    DelegatedResult result;
    result.taskId = task->task.taskId;
    result.agentId = agentId;
    result.startedAt = startTime;

    const ResourceLimits& limits = agent->limits;
    auto checkQuota = [&]() -> std::string {
        if (!m_config.enforceQuotas) return std::string();
        // Zero-budget resources are forbidden outright.
        std::string forbidden = agent->usage.forbiddenResource(limits);
        if (!forbidden.empty()) return forbidden;
        return agent->usage.violatedLimit(limits);
    };

    // Cooperative execution loop. The injected work function is synchronous;
    // we wrap it with quota checks and cancellation. Real agent loops would
    // observe the cancel token between steps, which the engine does.
    std::string preViolation = checkQuota();
    if (!preViolation.empty()) {
        result.success = false;
        result.errorMessage = "Resource limit '" + preViolation + "' already exceeded before start";
        result.completedAt = nowMs();
        result.usage = agent->usage;
        task->done = true;
        task->result = result;
        agent->lastError = result.errorMessage;
        agent->tasksFailed++;
        setAgentState(agent, AgentState::Failed);
        m_totalFailed++;
        m_idleCv.notify_all();
        return;
    }

    if (agent->cancelToken && agent->cancelToken->load()) {
        result.success = false;
        result.errorMessage = "Cancelled before start";
        result.completedAt = nowMs();
        result.usage = agent->usage;
        task->done = true;
        task->result = result;
        setAgentState(agent, AgentState::Cancelled);
        m_idleCv.notify_all();
        return;
    }

    try {
        if (!m_workFn) {
            // No engine wired. Fail honestly instead of inventing a result.
            throw std::runtime_error(
                "no work function configured (call setAgentWorkFn); refusing to report a result");
        }
        std::string output = m_workFn(*agent, task->task);
        result.output = output;
        result.success = true;

        // Deadline enforcement
        int64_t elapsed = nowMs() - startTime;
        if (task->task.deadlineMs > 0 && elapsed > task->task.deadlineMs) {
            result.success = false;
            result.errorMessage = "Deadline exceeded: " + std::to_string(elapsed) + "ms > " +
                           std::to_string(task->task.deadlineMs) + "ms";
            agent->tasksFailed++;
            m_totalFailed++;
            setAgentState(agent, AgentState::Failed);
        } else {
            agent->tasksCompleted++;
            m_totalCompleted++;
            setAgentState(agent, AgentState::Completed);
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = std::string("Exception: ") + e.what();
        agent->lastError = result.errorMessage;
        agent->tasksFailed++;
        m_totalFailed++;
        setAgentState(agent, AgentState::Failed);
    } catch (...) {
        result.success = false;
        result.errorMessage = "Unknown exception";
        agent->lastError = result.errorMessage;
        agent->tasksFailed++;
        m_totalFailed++;
        setAgentState(agent, AgentState::Failed);
    }

    int64_t endTime = nowMs();
    agent->usage.wallTimeMs = endTime - startTime;
    agent->usage.cpuTimeMs = agent->usage.wallTimeMs;   // no separate cpu accounting here
    result.completedAt = endTime;
    result.usage = agent->usage;

    task->done = true;
    task->result = result;

    std::ostringstream log;
    log << "{\"event\":\"task_finished\",\"task\":\"" << result.taskId
        << "\",\"success\":" << (result.success ? "true" : "false")
        << ",\"elapsedMs\":" << result.elapsedMs() << "}";
    auditLog(log.str());

    m_idleCv.notify_all();
}

DelegatedResult DelegationManager::waitForTask(const std::string& taskId, int timeoutMs) {
    int64_t start = nowMs();
    while (true) {
        std::shared_ptr<PendingTask> task;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_tasks.find(taskId);
            if (it != m_tasks.end()) task = it->second;
        }
        if (task && task->done) return task->result;

        if (nowMs() - start > timeoutMs) {
            DelegatedResult r;
            r.taskId = taskId;
            r.success = false;
            r.errorMessage = "Timeout waiting for task result";
            r.completedAt = nowMs();
            return r;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool DelegationManager::cancelAgent(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_agents.find(agentId);
    if (it == m_agents.end()) return false;
    if (it->second->cancelToken) it->second->cancelToken->store(true);

    // Cancel queued tasks
    for (auto& pair : m_tasks) {
        if (pair.second->agentId == agentId && !pair.second->done) {
            pair.second->result.success = false;
            pair.second->result.errorMessage = "Cancelled";
            pair.second->result.completedAt = nowMs();
            pair.second->done = true;
        }
    }
    return true;
}

void DelegationManager::cancelAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& pair : m_agents) {
        if (pair.second->cancelToken) pair.second->cancelToken->store(true);
    }
    for (auto& pair : m_tasks) {
        if (!pair.second->done) {
            pair.second->result.success = false;
            pair.second->result.errorMessage = "Cancelled";
            pair.second->result.completedAt = nowMs();
            pair.second->done = true;
        }
    }
    std::queue<std::string>().swap(m_readyQueue);
}

bool DelegationManager::cancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end() || it->second->done) return false;

    auto ait = m_agents.find(it->second->agentId);
    if (ait != m_agents.end() && ait->second->cancelToken) {
        ait->second->cancelToken->store(true);
    }
    it->second->result.success = false;
    it->second->result.errorMessage = "Cancelled";
    it->second->result.completedAt = nowMs();
    it->second->done = true;
    return true;
}

bool DelegationManager::sendMessage(const AgentMessage& message) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Recipient must exist (or be a broadcast with empty toAgentId).
    if (!message.toAgentId.empty() && m_agents.find(message.toAgentId) == m_agents.end()) {
        return false;
    }
    if (!message.fromAgentId.empty() && m_agents.find(message.fromAgentId) == m_agents.end()) {
        return false;
    }

    AgentMessage stored = message;
    if (stored.messageId.empty()) stored.messageId = makeId("msg");
    stored.sentAt = nowMs();

    size_t idx = m_messages.size();
    m_messages.push_back(stored);
    m_messageIndex[stored.toAgentId].push_back(idx);   // "" = broadcast bucket
    m_totalMessages++;

    auditLog("{\"event\":\"message\",\"id\":\"" + stored.messageId + "\",\"from\":\"" +
             stored.fromAgentId + "\",\"to\":\"" + stored.toAgentId + "\"}");

    if (m_messageCb) {
        // Call outside the lock would require copying; safe here since callbacks
        // are expected to be short-lived UI hooks.
        m_messageCb(stored);
    }
    return true;
}

std::vector<AgentMessage> DelegationManager::getMessagesFor(const std::string& agentId,
                                                            bool undeliveredOnly) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AgentMessage> out;

    // Broadcast bucket + agent-specific bucket.
    auto collect = [&](const std::string& key) {
        auto it = m_messageIndex.find(key);
        if (it == m_messageIndex.end()) return;
        for (size_t idx : it->second) {
            if (idx >= m_messages.size()) continue;
            const auto& m = m_messages[idx];
            if (undeliveredOnly && m.deliveredAt != 0) continue;
            out.push_back(m);
        }
    };
    collect("");            // broadcasts
    collect(agentId);      // direct
    return out;
}

void DelegationManager::ackMessages(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& m : m_messages) {
        if ((m.toAgentId.empty() || m.toAgentId == agentId)) m.deliveredAt = nowMs();
    }
}

bool DelegationManager::broadcast(const std::string& fromAgentId, const std::string& kind,
                                  const std::string& subject, const std::string& body) {
    AgentMessage msg;
    msg.fromAgentId = fromAgentId;
    msg.toAgentId = "";   // broadcast
    msg.kind = kind;
    msg.subject = subject;
    msg.body = body;
    return sendMessage(msg);
}

void DelegationManager::onAgentStateChanged(EventCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_stateCb = std::move(cb);
}

void DelegationManager::onMessage(MessageCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_messageCb = std::move(cb);
}

DelegationManager::Stats DelegationManager::getStats() const {
    Stats s;
    s.totalAgentsCreated = m_totalCreated.load();
    s.totalTasksCompleted = m_totalCompleted.load();
    s.totalTasksFailed = m_totalFailed.load();
    s.totalMessagesSent = m_totalMessages.load();
    s.activeAgents = m_activeAgents.load();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& pair : m_agents) {
        auto st = pair.second->state;
        if (st == AgentState::Running || st == AgentState::Paused) s.activeAgents++;
        else if (st == AgentState::Queued) s.queuedAgents++;
    }
    return s;
}

std::string DelegationManager::statusSummary() const {
    // Snapshot agent state under the lock, then build the string without it.
    // getStats() locks the same non-recursive mutex, so it must run unlocked.
    size_t agentCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        agentCount = m_agents.size();
    }
    auto stats = getStats();

    std::ostringstream oss;
    oss << "DelegationManager: " << agentCount << " agents ("
        << stats.activeAgents << " active, " << stats.queuedAgents << " queued, "
        << stats.totalAgentsCreated << " created), "
        << stats.totalTasksCompleted << " completed, "
        << stats.totalTasksFailed << " failed, "
        << stats.totalMessagesSent << " messages";
    return oss.str();
}

std::string DelegationManager::exportStateJSON() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream oss;
    auto escape = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        return out;
    };

    oss << "{\"agents\":[";
    bool first = true;
    for (const auto& pair : m_agents) {
        if (!first) oss << ",";
        first = false;
        const auto& a = *pair.second;
        oss << "{\"agentId\":\"" << escape(a.agentId) << "\","
            << "\"label\":\"" << escape(a.label) << "\","
            << "\"parent\":\"" << escape(a.parentAgentId) << "\","
            << "\"depth\":" << a.depth << ","
            << "\"state\":\"" << stateName(a.state) << "\","
            << "\"tasksCompleted\":" << a.tasksCompleted << ","
            << "\"tasksFailed\":" << a.tasksFailed << ","
            << "\"limitFraction\":" << a.limitFraction() << ","
            << "\"usage\":{\"tokens\":" << a.usage.tokensUsed
            << ",\"wallTimeMs\":" << a.usage.wallTimeMs
            << ",\"toolCalls\":" << a.usage.toolCalls << "}}";
    }
    oss << "],\"messages\":" << m_messages.size() << "}";
    return oss.str();
}

void DelegationManager::waitForIdle(int timeoutMs) {
    int64_t start = nowMs();
    while (true) {
        bool idle = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            idle = m_readyQueue.empty() && m_activeAgents.load() == 0;
            for (const auto& pair : m_tasks) {
                if (!pair.second->done) { idle = false; break; }
            }
        }
        if (idle) return;
        if (nowMs() - start > timeoutMs) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace Delegation
} // namespace RawrXD
