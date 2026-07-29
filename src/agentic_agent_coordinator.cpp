// AgenticAgentCoordinator implementation - C++20
#include "agentic_agent_coordinator.h"

#include "agentic_iterative_reasoning.h"
#include "agentic_loop_state.h"

<<<<<<< HEAD
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <utility>

<<<<<<< HEAD
namespace {
std::string generateId() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8) << (dis(gen) & 0xFFFFFFFFULL) << "-";
    ss << std::setw(4) << (dis(gen) & 0xFFFFULL) << "-";
    ss << std::setw(4) << ((dis(gen) & 0x0FFFULL) | 0x4000ULL) << "-";
    ss << std::setw(4) << ((dis(gen) & 0x3FFFULL) | 0x8000ULL) << "-";
    ss << std::setw(12) << (dis(gen) & 0xFFFFFFFFFFFFULL);
    return ss.str();
}

std::string toIsoLike(std::chrono::system_clock::time_point tp) {
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[64] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
=======
AgenticAgentCoordinator::AgenticAgentCoordinator(void* parent)
    : void(parent),
      m_coordinationStartTime(std::chrono::system_clock::time_point::currentDateTime())
{
}

AgenticAgentCoordinator::~AgenticAgentCoordinator()
{
             << m_agents.size() << "agents and"
             << m_assignments.size() << "task assignments";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
}  // namespace

AgenticAgentCoordinator::AgenticAgentCoordinator()
    : m_coordinationStartTime(std::chrono::system_clock::now()),
      m_lastCheckpointTime(m_coordinationStartTime) {}

AgenticAgentCoordinator::~AgenticAgentCoordinator() = default;

void AgenticAgentCoordinator::initialize(AgenticEngine* engine, CPUInference::CPUInferenceEngine* inference) {
    m_engine = engine;
    m_inference = inference;
    m_inferenceEngine = inference;
<<<<<<< HEAD
}

std::string AgenticAgentCoordinator::createAgent(AgentRole role) {
    const std::string agentId = generateId();
=======

}

// ===== AGENT MANAGEMENT =====

std::string AgenticAgentCoordinator::createAgent(AgentRole role)
{
    std::string agentId = QUuid::createUuid().toString();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    auto agent = std::make_unique<AgentInstance>();
    agent->agentId = agentId;
    agent->role = role;
    agent->reasoner = std::make_unique<AgenticIterativeReasoning>();
    agent->state = std::make_unique<AgenticLoopState>();
    agent->isAvailable = true;
    agent->utilization = 0.0f;
    agent->tasksCompleted = 0;
<<<<<<< HEAD
    agent->lastActive = std::chrono::system_clock::now();
    agent->currentTask.clear();
    agent->lastResult.clear();

    if (agent->reasoner) {
        agent->reasoner->initialize(m_engine, agent->state.get(), m_inferenceEngine);
    }
=======
    agent->lastActive = std::chrono::system_clock::time_point::currentDateTime();

    m_agents[agentId.toStdString()] = std::move(agent);

    agentCreated(agentId, std::string::number(static_cast<int>(role)));

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    m_agents[agentId] = std::move(agent);
    return agentId;
}

<<<<<<< HEAD
void AgenticAgentCoordinator::removeAgent(const std::string& agentId) {
    m_agents.erase(agentId);
}

AgenticAgentCoordinator::AgentInstance* AgenticAgentCoordinator::getAgent(const std::string& agentId) {
    auto it = m_agents.find(agentId);
    return it != m_agents.end() ? it->second.get() : nullptr;
=======
void AgenticAgentCoordinator::removeAgent(const std::string& agentId)
{
    m_agents.erase(agentId.toStdString());
    agentRemoved(agentId);

}

AgenticAgentCoordinator::AgentInstance* AgenticAgentCoordinator::getAgent(const std::string& agentId)
{
    auto it = m_agents.find(agentId.toStdString());
    if (it != m_agents.end()) {
        return it->second.get();
    }
    return nullptr;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::vector<AgenticAgentCoordinator::AgentInstance*> AgenticAgentCoordinator::getAvailableAgents(AgentRole role) {
    std::vector<AgentInstance*> out;
    for (auto& kv : m_agents) {
        if (kv.second->isAvailable && kv.second->role == role) {
            out.push_back(kv.second.get());
        }
    }
    return out;
}

<<<<<<< HEAD
std::vector<std::string> AgenticAgentCoordinator::getAllAgentIds() {
    std::vector<std::string> ids;
    ids.reserve(m_agents.size());
    for (const auto& kv : m_agents) {
        ids.push_back(kv.first);
=======
std::vector<std::string> AgenticAgentCoordinator::getAllAgentIds() const
{
    std::vector<std::string> ids;
    for (const auto& pair : m_agents) {
        ids.append(std::string::fromStdString(pair.first));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return ids;
}

<<<<<<< HEAD
AgentStatus AgenticAgentCoordinator::getAgentStatus(const std::string& agentId) {
    AgentStatus st{};
    auto* agent = getAgent(agentId);
    if (!agent) {
        st.agent_id = agentId;
        st.role = static_cast<int>(AgentRole::Developer);
        st.available = false;
        st.utilization = 0.0f;
        st.tasks_completed = 0;
        st.last_active = "";
        return st;
=======
void* AgenticAgentCoordinator::getAgentStatus(const std::string& agentId)
{
    void* status;

    auto agent = getAgent(agentId);
    if (!agent) return status;

    status["agent_id"] = agentId;
    status["role"] = static_cast<int>(agent->role);
    status["available"] = agent->isAvailable;
    status["utilization"] = agent->utilization;
    status["tasks_completed"] = agent->tasksCompleted;
    status["last_active"] = agent->lastActive.toString(//ISODate);

    return status;
}

void* AgenticAgentCoordinator::getAllAgentStatuses()
{
    void* statuses;

    for (const auto& pair : m_agents) {
        statuses.append(getAgentStatus(pair.second->agentId));
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    st.agent_id = agent->agentId;
    st.role = static_cast<int>(agent->role);
    st.available = agent->isAvailable;
    st.utilization = agent->utilization;
    st.tasks_completed = agent->tasksCompleted;
    st.last_active = toIsoLike(agent->lastActive);
    return st;
}

std::vector<AgentStatus> AgenticAgentCoordinator::getAllAgentStatuses() {
    std::vector<AgentStatus> statuses;
    statuses.reserve(m_agents.size());
    for (const auto& kv : m_agents) {
        statuses.push_back(getAgentStatus(kv.first));
    }
    return statuses;
}

std::string AgenticAgentCoordinator::assignTask(
    const std::string& taskDescription,
    const std::map<std::string, std::string>& parameters,
    AgentRole requiredRole) {
    const std::string taskId = generateId();

<<<<<<< HEAD
    std::vector<AgentInstance*> candidates = getAvailableAgents(requiredRole);
    AgentInstance* best = nullptr;
    for (auto* a : candidates) {
        if (!best || a->utilization < best->utilization) best = a;
    }

    if (!best) {
        return {};
=======
std::string AgenticAgentCoordinator::assignTask(
    const std::string& taskDescription,
    const void*& parameters,
    AgentRole requiredRole)
{
    std::string taskId = QUuid::createUuid().toString();

    // Find best agent for task
    std::string agentId = selectBestAgentForTask(taskDescription);

    if (agentId.empty()) {
        return "";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    auto assignment = std::make_unique<TaskAssignment>();
    assignment->taskId = taskId;
    assignment->assignedAgentId = best->agentId;
    assignment->requiredRole = static_cast<int>(requiredRole);
    assignment->description = taskDescription;
    assignment->parameters = parameters;
<<<<<<< HEAD
    assignment->assignedTime = std::chrono::system_clock::now();
=======
    assignment->assignedTime = std::chrono::system_clock::time_point::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    assignment->status = "assigned";

    best->isAvailable = false;
    best->currentTask = taskDescription;
    best->utilization = std::max(best->utilization, 0.7f);
    best->lastActive = assignment->assignedTime;

    m_assignments[taskId] = std::move(assignment);
    ++m_totalTasksAssigned;

    if (m_taskAssignedCallback) {
        m_taskAssignedCallback(taskId, best->agentId);
    }

<<<<<<< HEAD
    return taskId;
}

bool AgenticAgentCoordinator::executeAssignedTask(const std::string& taskId) {
    auto it = m_assignments.find(taskId);
    if (it == m_assignments.end()) return false;
=======
    taskAssigned(taskId, agentId);


    return taskId;
}

bool AgenticAgentCoordinator::executeAssignedTask(const std::string& taskId)
{
    auto it = m_assignments.find(taskId.toStdString());
    if (it == m_assignments.end()) {
        return false;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    TaskAssignment& task = *it->second;
    task.status = "running";

    auto* agent = getAgent(task.assignedAgentId);
    const auto start = std::chrono::system_clock::now();

    if (!agent) {
        task.status = "failed";
        task.result["error"] = "assigned agent not found";
        return false;
    }

<<<<<<< HEAD
    std::string summary = "completed";
    if (agent->reasoner) {
        auto rr = agent->reasoner->reason(task.description);
        if (!rr.success) {
            task.status = "failed";
            task.result["error"] = rr.error;
            agent->lastResult = rr.error;
            agent->isAvailable = true;
            agent->currentTask.clear();
            agent->utilization = std::max(0.0f, agent->utilization - 0.4f);
            return false;
=======
    // Execute reasoning on the agent
    if (agent->reasoner && agent->state) {
        agent->reasoner->initialize(m_engine, agent->state.get(), m_inferenceEngine);

        auto result = agent->reasoner->reason(assignment->description);

        assignment->result["success"] = result.success;
        assignment->result["output"] = result.result;
        assignment->completionTime = std::chrono::system_clock::time_point::currentDateTime();
        assignment->status = result.success ? "completed" : "failed";

        agent->lastResult = result.result;
        agent->lastActive = std::chrono::system_clock::time_point::currentDateTime();
        agent->isAvailable = true;
        agent->utilization = 0.0f;
        agent->tasksCompleted++;

        m_totalTasksCompleted++;

        // Record task duration
        int duration = assignment->assignedTime.msecsTo(assignment->completionTime);
        m_taskDurations.push_back({assignment->description, duration});

        if (result.success) {
            taskCompleted(taskId);
        } else {
            taskFailed(taskId, "Execution failed");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
        summary = rr.result;
    }

    task.status = "completed";
    task.result["summary"] = summary;
    task.completionTime = std::chrono::system_clock::now();

<<<<<<< HEAD
    const auto ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
        task.completionTime - start).count());
    m_taskDurations.push_back({task.description, ms});

    agent->lastResult = summary;
    agent->isAvailable = true;
    agent->currentTask.clear();
    agent->utilization = std::max(0.0f, agent->utilization - 0.5f);
    agent->tasksCompleted += 1;
    agent->lastActive = task.completionTime;

    ++m_totalTasksCompleted;
    updateAgentMetrics(agent->agentId);

    if (m_taskCompletedCallback) {
        m_taskCompletedCallback(taskId);
    }
    return true;
}

std::string AgenticAgentCoordinator::getTaskStatus(const std::string& taskId) {
    auto it = m_assignments.find(taskId);
    if (it == m_assignments.end()) return "unknown";
    return it->second->status;
}

std::map<std::string, std::string> AgenticAgentCoordinator::getTaskResult(const std::string& taskId) {
    auto it = m_assignments.find(taskId);
    if (it == m_assignments.end()) return {};
    return it->second->result;
}

std::vector<std::map<std::string, std::string>> AgenticAgentCoordinator::getAllTaskStatuses() {
    std::vector<std::map<std::string, std::string>> rows;
    rows.reserve(m_assignments.size());
    for (const auto& kv : m_assignments) {
        const TaskAssignment& t = *kv.second;
        std::map<std::string, std::string> row;
        row["taskId"] = t.taskId;
        row["agentId"] = t.assignedAgentId;
        row["description"] = t.description;
        row["status"] = t.status;
        row["requiredRole"] = std::to_string(t.requiredRole);
        rows.push_back(std::move(row));
    }
    return rows;
}

std::vector<std::string> AgenticAgentCoordinator::decomposeLargeTask(const std::string& goal) {
    std::vector<std::string> out;
    if (goal.empty()) return out;

    std::string chunk;
    std::istringstream iss(goal);
    while (std::getline(iss, chunk, ';')) {
        if (!chunk.empty()) out.push_back(chunk);
    }
    if (out.empty()) {
        out.push_back("Analyze: " + goal);
        out.push_back("Implement: " + goal);
        out.push_back("Validate: " + goal);
    }
    return out;
}

void AgenticAgentCoordinator::synchronizeAgentStates() {
    for (const auto& kv : m_agents) {
        syncStateWithAgent(kv.first);
    }
}

bool AgenticAgentCoordinator::detectStateConflict(const std::string& agentId1, const std::string& agentId2) {
    auto* a1 = getAgent(agentId1);
    auto* a2 = getAgent(agentId2);
    if (!a1 || !a2) return false;
    if (a1->isAvailable || a2->isAvailable) return false;
    return !a1->currentTask.empty() && a1->currentTask == a2->currentTask;
}

std::string AgenticAgentCoordinator::resolveStateConflict(const std::string& agentId1, const std::string& agentId2) {
    if (!detectStateConflict(agentId1, agentId2)) {
        return "no-conflict";
    }
    auto* a2 = getAgent(agentId2);
    if (a2) {
        a2->isAvailable = true;
        a2->currentTask.clear();
        a2->utilization = std::max(0.0f, a2->utilization - 0.3f);
    }
    recordConflict(agentId1, agentId2, "duplicate currentTask", "released second agent");
    return "released-second-agent";
}

bool AgenticAgentCoordinator::buildConsensus(const std::vector<std::string>& agentIds, const std::string& question) {
    if (agentIds.empty()) return false;
    std::map<std::string, int> votes;
    for (const auto& id : agentIds) {
        votes[getAgentOpinion(id, question)]++;
    }
    int best = 0;
    for (const auto& kv : votes) best = std::max(best, kv.second);
    return best * 2 >= static_cast<int>(agentIds.size());
}

std::string AgenticAgentCoordinator::resolveDisagreement(const std::vector<std::string>& agentIds) {
    if (agentIds.empty()) return {};
    return getAgentOpinion(agentIds.front(), "resolve-disagreement");
}

void AgenticAgentCoordinator::allocateResources(const std::string& agentId, float cpuShare, float /*memoryShare*/) {
    auto* a = getAgent(agentId);
    if (!a) return;
    a->utilization = std::clamp(cpuShare, 0.0f, 1.0f);
    a->lastActive = std::chrono::system_clock::now();
}

void AgenticAgentCoordinator::rebalanceResources() {
    rebalanceWorkload();
}

std::map<std::string, float> AgenticAgentCoordinator::getCoordinationMetrics() const {
    std::map<std::string, float> m;
    m["total_utilization"] = getTotalUtilization();
    m["tasks_assigned"] = static_cast<float>(m_totalTasksAssigned);
    m["tasks_completed"] = static_cast<float>(m_totalTasksCompleted);
    m["task_completion_rate"] = m_totalTasksAssigned > 0
        ? static_cast<float>(m_totalTasksCompleted) / static_cast<float>(m_totalTasksAssigned)
        : 0.0f;
    m["avg_task_duration_ms"] = getAverageTaskDuration();
    m["total_conflicts"] = static_cast<float>(m_totalConflicts);
    return m;
}

float AgenticAgentCoordinator::getTotalUtilization() const {
    float total = 0.0f;
    for (const auto& kv : m_agents) total += kv.second->utilization;
    return total;
}

int AgenticAgentCoordinator::getTotalTasksCompleted() const {
    return m_totalTasksCompleted;
}

float AgenticAgentCoordinator::getAverageTaskDuration() const {
    if (m_taskDurations.empty()) return 0.0f;
    long long total = 0;
    for (const auto& p : m_taskDurations) total += p.second;
    return static_cast<float>(total) / static_cast<float>(m_taskDurations.size());
}

std::vector<AgentConflict> AgenticAgentCoordinator::getConflictHistory() {
    return m_conflicts;
}

std::string AgenticAgentCoordinator::selectBestAgentForTask(const std::string& taskDescription) {
    AgentRole targetRole = AgentRole::Developer;
    const std::string lower = taskDescription;
    if (lower.find("test") != std::string::npos) targetRole = AgentRole::Tester;
    if (lower.find("review") != std::string::npos) targetRole = AgentRole::Reviewer;
    if (lower.find("analy") != std::string::npos) targetRole = AgentRole::Analyzer;
    if (lower.find("arch") != std::string::npos) targetRole = AgentRole::Architect;

    std::vector<AgentInstance*> candidates = getAvailableAgents(targetRole);
    if (candidates.empty()) {
        for (const auto& kv : m_agents) {
            if (kv.second->isAvailable) candidates.push_back(kv.second.get());
        }
    }
    if (candidates.empty()) return {};

    auto* best = *std::min_element(
        candidates.begin(), candidates.end(),
        [](const AgentInstance* a, const AgentInstance* b) {
            return a->utilization < b->utilization;
        });
    return best ? best->agentId : std::string();
}

void AgenticAgentCoordinator::rebalanceWorkload() {
    if (m_agents.empty()) return;
    const float avg = getTotalUtilization() / static_cast<float>(m_agents.size());
    for (auto& kv : m_agents) {
        if (kv.second->isAvailable) {
            kv.second->utilization = std::min(kv.second->utilization, avg);
        }
    }
}

AgenticAgentCoordinator::GlobalState AgenticAgentCoordinator::getGlobalState() {
    GlobalState s;
    s.agents = getAllAgentStatuses();
    s.tasks = getAllTaskStatuses();
    s.metrics = getCoordinationMetrics();
    return s;
}

bool AgenticAgentCoordinator::restoreGlobalState(const GlobalState& state) {
    m_agents.clear();
    m_assignments.clear();
    m_taskDurations.clear();
    m_conflicts.clear();

    for (const auto& a : state.agents) {
        auto agent = std::make_unique<AgentInstance>();
        agent->agentId = a.agent_id;
        agent->role = static_cast<AgentRole>(a.role);
        agent->reasoner = std::make_unique<AgenticIterativeReasoning>();
        agent->state = std::make_unique<AgenticLoopState>();
        agent->isAvailable = a.available;
        agent->utilization = std::clamp(a.utilization, 0.0f, 1.0f);
        agent->tasksCompleted = a.tasks_completed;
        agent->lastActive = std::chrono::system_clock::now();
        if (agent->reasoner) {
            agent->reasoner->initialize(m_engine, agent->state.get(), m_inferenceEngine);
        }
        m_agents[agent->agentId] = std::move(agent);
=======
std::string AgenticAgentCoordinator::getTaskStatus(const std::string& taskId)
{
    auto it = m_assignments.find(taskId.toStdString());
    if (it != m_assignments.end()) {
        return it->second->status;
    }
    return "unknown";
}

void* AgenticAgentCoordinator::getTaskResult(const std::string& taskId)
{
    auto it = m_assignments.find(taskId.toStdString());
    if (it != m_assignments.end()) {
        return it->second->result;
    }
    return void*();
}

void* AgenticAgentCoordinator::getAllTaskStatuses()
{
    void* statuses;

    for (const auto& pair : m_assignments) {
        void* status;
        status["task_id"] = pair.second->taskId;
        status["agent_id"] = pair.second->assignedAgentId;
        status["description"] = pair.second->description;
        status["status"] = pair.second->status;
        status["assigned_time"] = pair.second->assignedTime.toString(//ISODate);

        statuses.append(status);
    }

    return statuses;
}

// ===== COORDINATION MECHANISMS =====

void* AgenticAgentCoordinator::decomposeLargeTask(const std::string& goal)
{
    void* subtasks;

    // Use analyzer agent to decompose
    auto analyzers = getAvailableAgents(AgentRole::Analyzer);
    if (analyzers.empty()) {
        return subtasks;
    }

    // Would call analyzer to decompose task
    return subtasks;
}

void AgenticAgentCoordinator::synchronizeAgentStates()
{
    for (auto& pair : m_agents) {
        syncStateWithAgent(pair.second->agentId);
    }

}

bool AgenticAgentCoordinator::detectStateConflict(const std::string& agentId1, const std::string& agentId2)
{
    auto agent1 = getAgent(agentId1);
    auto agent2 = getAgent(agentId2);

    if (!agent1 || !agent2 || !agent1->state || !agent2->state) {
        return false;
    }

    // Compare states
    void* state1 = agent1->state->getAllMemory();
    void* state2 = agent2->state->getAllMemory();

    return state1 != state2;
}

std::string AgenticAgentCoordinator::resolveStateConflict(const std::string& agentId1, const std::string& agentId2)
{
    auto agent1 = getAgent(agentId1);
    auto agent2 = getAgent(agentId2);

    if (!agent1 || !agent2) {
        return "Agent not found";
    }

    void* state1 = agent1->state->getAllMemory();
    void* state2 = agent2->state->getAllMemory();

    std::string resolution = reconcileConflictingStates(state1, state2);

    recordConflict(agentId1, agentId2, "State conflict", resolution);

    stateConflictDetected(agentId1, agentId2);
    stateConflictResolved(resolution);

    return resolution;
}

bool AgenticAgentCoordinator::buildConsensus(const std::vector<std::string>& agentIds, const std::string& question)
{
    std::vector<std::string> opinions;

    for (const auto& agentId : agentIds) {
        auto agent = getAgent(agentId);
        if (agent && agent->state) {
            opinions.append(getAgentOpinion(agentId, question));
        }
    }

    // Check if opinions converge
    return opinions.size() > 0;
}

std::string AgenticAgentCoordinator::getAgentOpinion(const std::string& agentId, const std::string& question)
{
    // Would query agent for its opinion on the question
    return "Agent opinion";
}

std::string AgenticAgentCoordinator::resolveDisagreement(const std::vector<std::string>& agentIds)
{
    // Use consensus algorithm or voting to resolve
    return "Resolved through voting";
}

void AgenticAgentCoordinator::allocateResources(
    const std::string& agentId,
    float cpuShare,
    float memoryShare)
{
    auto agent = getAgent(agentId);
    if (agent) {
    }
}

void AgenticAgentCoordinator::rebalanceResources()
{
    // Reallocate resources based on utilization
}

// ===== MONITORING =====

void* AgenticAgentCoordinator::getCoordinationMetrics() const
{
    void* metrics;

    metrics["total_agents"] = static_cast<int>(m_agents.size());
    metrics["total_tasks_assigned"] = m_totalTasksAssigned;
    metrics["total_tasks_completed"] = m_totalTasksCompleted;
    metrics["total_utilization"] = getTotalUtilization();
    metrics["average_task_duration"] = getAverageTaskDuration();
    metrics["conflicts_detected"] = m_conflicts.size();

    return metrics;
}

float AgenticAgentCoordinator::getTotalUtilization() const
{
    if (m_agents.empty()) return 0.0f;

    float total = 0.0f;
    for (const auto& pair : m_agents) {
        total += pair.second->utilization;
    }

    return total / m_agents.size();
}

int AgenticAgentCoordinator::getTotalTasksCompleted() const
{
    return m_totalTasksCompleted;
}

float AgenticAgentCoordinator::getAverageTaskDuration() const
{
    if (m_taskDurations.empty()) return 0.0f;

    int totalDuration = 0;
    for (const auto& pair : m_taskDurations) {
        totalDuration += pair.second;
    }

    return totalDuration / static_cast<float>(m_taskDurations.size());
}

void* AgenticAgentCoordinator::getConflictHistory()
{
    void* history;

    for (const auto& conflict : m_conflicts) {
        void* obj;
        obj["conflict_id"] = conflict.conflictId;
        obj["agent1"] = conflict.agent1Id;
        obj["agent2"] = conflict.agent2Id;
        obj["reason"] = conflict.conflictReason;
        obj["resolution"] = conflict.resolution;
        obj["timestamp"] = conflict.timestamp.toString(//ISODate);

        history.append(obj);
    }

    return history;
}

// ===== LOAD BALANCING =====

std::string AgenticAgentCoordinator::selectBestAgentForTask(const std::string& taskDescription)
{
    // Find least utilized agent
    AgentInstance* bestAgent = nullptr;
    float minUtilization = 2.0f;

    for (auto& pair : m_agents) {
        if (pair.second->isAvailable && pair.second->utilization < minUtilization) {
            minUtilization = pair.second->utilization;
            bestAgent = pair.second.get();
        }
    }

    return bestAgent ? bestAgent->agentId : std::string();
}

void AgenticAgentCoordinator::rebalanceWorkload()
{
    // Redistribute tasks from over-utilized to under-utilized agents
}

// ===== STATE MANAGEMENT =====

void* AgenticAgentCoordinator::getGlobalState()
{
    void* globalState;
    globalState["agents"] = getAllAgentStatuses();
    globalState["tasks"] = getAllTaskStatuses();
    globalState["metrics"] = getCoordinationMetrics();

    return globalState;
}

bool AgenticAgentCoordinator::restoreGlobalState(const void*& state)
{
    // Restore agent and task states
    return true;
}

void AgenticAgentCoordinator::saveCheckpoint()
{
    m_lastCheckpoint = getGlobalState();
    m_lastCheckpointTime = std::chrono::system_clock::time_point::currentDateTime();

}

bool AgenticAgentCoordinator::restoreFromCheckpoint()
{
    if (m_lastCheckpoint.empty()) {
        return false;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }

    m_totalTasksAssigned = static_cast<int>(state.metrics.count("tasks_assigned")
        ? state.metrics.at("tasks_assigned") : 0.0f);
    m_totalTasksCompleted = static_cast<int>(state.metrics.count("tasks_completed")
        ? state.metrics.at("tasks_completed") : 0.0f);
    m_totalConflicts = static_cast<int>(state.metrics.count("total_conflicts")
        ? state.metrics.at("total_conflicts") : 0.0f);

    return true;
}

void AgenticAgentCoordinator::saveCheckpoint() {
    m_lastCheckpoint = getGlobalState();
    m_lastCheckpointTime = std::chrono::system_clock::now();
}

bool AgenticAgentCoordinator::restoreFromCheckpoint() {
    if (m_lastCheckpoint.agents.empty() && m_lastCheckpoint.tasks.empty() && m_lastCheckpoint.metrics.empty()) {
        return false;
    }
    return restoreGlobalState(m_lastCheckpoint);
}

<<<<<<< HEAD
std::string AgenticAgentCoordinator::getAgentOpinion(const std::string& agentId, const std::string& question) {
    auto* agent = getAgent(agentId);
    if (!agent) return "unknown";
    return "agent:" + agentId + " opinion on " + question;
}

std::string AgenticAgentCoordinator::reconcileConflictingStates(
    const std::map<std::string, std::string>& state1,
    const std::map<std::string, std::string>& state2) {
    std::map<std::string, std::string> merged = state1;
    for (const auto& kv : state2) {
        merged[kv.first] = kv.second;
=======
// ===== PRIVATE HELPERS =====

void AgenticAgentCoordinator::syncStateWithAgent(const std::string& agentId)
{
    auto agent = getAgent(agentId);
    if (!agent || !agent->state) return;

    // Synchronize agent state with global coordinator state
}

std::string AgenticAgentCoordinator::reconcileConflictingStates(
    const void*& state1,
    const void*& state2)
{
    // Merge conflicting states intelligently
    return "States reconciled using merge strategy";
}

std::string AgenticAgentCoordinator::selectResolutionStrategy(const std::string& conflictReason)
{
    if (conflictReason.contains("state")) {
        return "merge";
    } else if (conflictReason.contains("priority")) {
        return "priority_based";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    std::ostringstream oss;
    bool first = true;
    for (const auto& kv : merged) {
        if (!first) oss << ";";
        first = false;
        oss << kv.first << "=" << kv.second;
    }
    return oss.str();
}

void AgenticAgentCoordinator::syncStateWithAgent(const std::string& agentId) {
    auto* a = getAgent(agentId);
    if (!a) return;
    a->lastActive = std::chrono::system_clock::now();
}

void AgenticAgentCoordinator::recordConflict(
    const std::string& agent1,
    const std::string& agent2,
    const std::string& reason,
<<<<<<< HEAD
    const std::string& resolution) {
    AgentConflict c{};
    c.conflictId = generateId();
    c.agent1Id = agent1;
    c.agent2Id = agent2;
    c.conflictReason = reason;
    c.resolution = resolution;
    c.timestamp = std::chrono::system_clock::now();
    m_conflicts.push_back(std::move(c));
    ++m_totalConflicts;
}

void AgenticAgentCoordinator::updateAgentMetrics(const std::string& agentId) {
    auto* a = getAgent(agentId);
    if (!a) return;
    if (a->isAvailable) {
        a->utilization = std::max(0.0f, a->utilization - 0.1f);
    } else {
        a->utilization = std::min(1.0f, a->utilization + 0.1f);
    }
}

// ── Sovereign Autonomy Runtime Integration ──

void AgenticAgentCoordinator::initializeSovereignRuntime() {
    if (m_sovereignRuntime) return;
    RawrXD::Autonomy::RuntimeConfig config;
    config.enable_reflection = true;
    config.enable_critic = true;
    config.enable_replanning = true;
    config.max_concurrent_missions = 5;
    config.tick_interval_ms = 100;
    m_sovereignRuntime = std::make_shared<RawrXD::Autonomy::SovereignAgentRuntime>(config);
    m_sovereignRuntime->Initialize();
    m_sovereignRuntime->SetLogCallback([](const std::string& msg) {
        // Could forward to IDE logger
    });
    m_sovereignRuntime->SetStatusCallback([](const std::string& status) {
        // Could forward to IDE status bar
    });
}

std::shared_ptr<RawrXD::Autonomy::SovereignAgentRuntime> AgenticAgentCoordinator::getSovereignRuntime() const {
    return m_sovereignRuntime;
}

std::string AgenticAgentCoordinator::launchSovereignMission(const std::string& name, const std::string& goal) {
    if (!m_sovereignRuntime) initializeSovereignRuntime();
    return m_sovereignRuntime->LaunchMission(name, goal);
}

bool AgenticAgentCoordinator::cancelSovereignMission(const std::string& missionId) {
    if (!m_sovereignRuntime) return false;
    return m_sovereignRuntime->CancelMission(missionId);
}

RawrXD::Autonomy::MissionState AgenticAgentCoordinator::getSovereignMissionState(const std::string& missionId) const {
    if (!m_sovereignRuntime) return RawrXD::Autonomy::MissionState::Failed;
    return m_sovereignRuntime->GetMissionState(missionId);
}

float AgenticAgentCoordinator::getSovereignMissionProgress(const std::string& missionId) const {
    if (!m_sovereignRuntime) return 0.0f;
    return m_sovereignRuntime->GetMissionProgress(missionId);
}

std::vector<std::string> AgenticAgentCoordinator::getActiveSovereignMissions() const {
    if (!m_sovereignRuntime) return {};
    return m_sovereignRuntime->GetActiveMissions();
=======
    const std::string& resolution)
{
    AgentConflict conflict;
    conflict.conflictId = QUuid::createUuid().toString();
    conflict.agent1Id = agent1;
    conflict.agent2Id = agent2;
    conflict.conflictReason = reason;
    conflict.resolution = resolution;
    conflict.timestamp = std::chrono::system_clock::time_point::currentDateTime();

    m_conflicts.push_back(conflict);
    m_totalConflicts++;
}

void AgenticAgentCoordinator::updateAgentMetrics(const std::string& agentId)
{
    auto agent = getAgent(agentId);
    if (!agent) return;

    // Calculate and update metrics
    coordinationMetricsUpdated();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}


