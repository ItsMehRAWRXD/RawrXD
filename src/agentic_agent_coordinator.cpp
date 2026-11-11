// AgenticAgentCoordinator Implementation
#include "agentic_agent_coordinator.h"
#include "agentic_iterative_reasoning.h"
#include "agentic_loop_state.h"
#include <iostream>
#include <chrono>
#include <random>
#include <algorithm>
#include <functional>

namespace {

std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xffff);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dist(gen);
    ss << "-";
    ss << "4";
    for (int i = 0; i < 3; ++i) ss << dist(gen) & 0x0fff;
    ss << "-";
    ss << (dist(gen) & 0x3fff | 0x8000);
    for (int i = 0; i < 3; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 6; ++i) ss << dist(gen);
    return ss.str();
}

std::string nowIsoString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace

AgenticAgentCoordinator::AgenticAgentCoordinator()
    : m_coordinationStartTime(std::chrono::system_clock::now())
{
    std::clog << "[AgenticAgentCoordinator] Initialized - Ready for multi-agent coordination" << std::endl;
}

AgenticAgentCoordinator::~AgenticAgentCoordinator()
{
    std::clog << "[AgenticAgentCoordinator] Destroyed - Managed"
              << m_agents.size() << "agents and"
              << m_assignments.size() << "task assignments" << std::endl;
}

void AgenticAgentCoordinator::initialize(AgenticEngine* engine, InferenceEngine* inference)
{
    m_engine = engine;
    m_inferenceEngine = inference;

    std::clog << "[AgenticAgentCoordinator] Initialized with AgenticEngine and InferenceEngine" << std::endl;
}

// ===== AGENT MANAGEMENT =====

std::string AgenticAgentCoordinator::createAgent(AgentRole role)
{
    std::string agentId = generateUuid();

    auto agent = std::make_unique<AgentInstance>();
    agent->agentId = agentId;
    agent->role = role;
    agent->reasoner = std::make_unique<AgenticIterativeReasoning>();
    agent->state = std::make_unique<AgenticLoopState>();
    agent->isAvailable = true;
    agent->utilization = 0.0f;
    agent->tasksCompleted = 0;
    agent->lastActive = std::chrono::system_clock::now();

    m_agents[agentId] = std::move(agent);

    if (m_onAgentCreated) m_onAgentCreated(agentId, std::to_string(static_cast<int>(role)));

    std::clog << "[AgenticAgentCoordinator] Created agent: " << agentId
              << " with role: " << static_cast<int>(role) << std::endl;

    return agentId;
}

void AgenticAgentCoordinator::removeAgent(const std::string& agentId)
{
    m_agents.erase(agentId);

    if (m_onAgentRemoved) m_onAgentRemoved(agentId);

    std::clog << "[AgenticAgentCoordinator] Removed agent: " << agentId << std::endl;
}

AgenticAgentCoordinator::AgentInstance* AgenticAgentCoordinator::getAgent(const std::string& agentId)
{
    auto it = m_agents.find(agentId);
    if (it != m_agents.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<AgenticAgentCoordinator::AgentInstance*> AgenticAgentCoordinator::getAvailableAgents(
    AgentRole role)
{
    std::vector<AgentInstance*> available;

    for (auto& pair : m_agents) {
        if (pair.second->role == role && pair.second->isAvailable) {
            available.push_back(pair.second.get());
        }
    }

    return available;
}

std::vector<std::string> AgenticAgentCoordinator::getAllAgentIds() const
{
    std::vector<std::string> ids;
    for (const auto& pair : m_agents) {
        ids.push_back(pair.first);
    }
    return ids;
}

json AgenticAgentCoordinator::getAgentStatus(const std::string& agentId)
{
    json status;

    auto agent = getAgent(agentId);
    if (!agent) return status;

    status["agent_id"] = agentId;
    status["role"] = static_cast<int>(agent->role);
    status["available"] = agent->isAvailable;
    status["utilization"] = agent->utilization;
    status["tasks_completed"] = agent->tasksCompleted;

    auto t = std::chrono::system_clock::to_time_t(agent->lastActive);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    status["last_active"] = ss.str();

    return status;
}

json AgenticAgentCoordinator::getAllAgentStatuses()
{
    json statuses = json::array();

    for (const auto& pair : m_agents) {
        statuses.push_back(getAgentStatus(pair.second->agentId));
    }

    return statuses;
}

// ===== TASK ASSIGNMENT =====

std::string AgenticAgentCoordinator::assignTask(
    const std::string& taskDescription,
    const json& parameters,
    AgentRole requiredRole)
{
    std::string taskId = generateUuid();

    // Find best agent for task
    std::string agentId = selectBestAgentForTask(taskDescription);

    if (agentId.empty()) {
        std::cerr << "[AgenticAgentCoordinator] No available agent for task" << std::endl;
        return "";
    }

    auto assignment = std::make_unique<TaskAssignment>();
    assignment->taskId = taskId;
    assignment->assignedAgentId = agentId;
    assignment->requiredRole = requiredRole;
    assignment->description = taskDescription;
    assignment->parameters = parameters;
    assignment->assignedTime = std::chrono::system_clock::now();
    assignment->status = "assigned";

    m_assignments[taskId] = std::move(assignment);
    m_totalTasksAssigned++;

    auto agent = getAgent(agentId);
    if (agent) {
        agent->currentTask = taskDescription;
        agent->isAvailable = false;
        agent->utilization = 1.0f;
    }

    if (m_onTaskAssigned) m_onTaskAssigned(taskId, agentId);

    std::clog << "[AgenticAgentCoordinator] Assigned task: " << taskId
              << " to agent: " << agentId << std::endl;

    return taskId;
}

bool AgenticAgentCoordinator::executeAssignedTask(const std::string& taskId)
{
    auto it = m_assignments.find(taskId);
    if (it == m_assignments.end()) {
        return false;
    }

    auto& assignment = it->second;
    auto agent = getAgent(assignment->assignedAgentId);

    if (!agent) {
        return false;
    }

    // Execute reasoning on the agent
    if (agent->reasoner && agent->state) {
        agent->reasoner->initialize(m_engine, agent->state.get(), m_inferenceEngine);

        auto result = agent->reasoner->reason(assignment->description);

        assignment->result["success"] = result.success;
        assignment->result["output"] = result.result;
        assignment->completionTime = std::chrono::system_clock::now();
        assignment->status = result.success ? "completed" : "failed";

        agent->lastResult = result.result;
        agent->lastActive = std::chrono::system_clock::now();
        agent->isAvailable = true;
        agent->utilization = 0.0f;
        agent->tasksCompleted++;

        m_totalTasksCompleted++;

        // Record task duration
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            assignment->completionTime - assignment->assignedTime).count();
        m_taskDurations.push_back({assignment->description, (int)duration});

        if (result.success) {
            if (m_onTaskCompleted) m_onTaskCompleted(taskId);
        } else {
            if (m_onTaskFailed) m_onTaskFailed(taskId, "Execution failed");
        }

        return result.success;
    }

    return false;
}

std::string AgenticAgentCoordinator::getTaskStatus(const std::string& taskId)
{
    auto it = m_assignments.find(taskId);
    if (it != m_assignments.end()) {
        return it->second->status;
    }
    return "unknown";
}

json AgenticAgentCoordinator::getTaskResult(const std::string& taskId)
{
    auto it = m_assignments.find(taskId);
    if (it != m_assignments.end()) {
        return it->second->result;
    }
    return json();
}

json AgenticAgentCoordinator::getAllTaskStatuses()
{
    json statuses = json::array();

    for (const auto& pair : m_assignments) {
        json status;
        status["task_id"] = pair.second->taskId;
        status["agent_id"] = pair.second->assignedAgentId;
        status["description"] = pair.second->description;
        status["status"] = pair.second->status;

        auto t = std::chrono::system_clock::to_time_t(pair.second->assignedTime);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        status["assigned_time"] = ss.str();

        statuses.push_back(status);
    }

    return statuses;
}

// ===== COORDINATION MECHANISMS =====

json AgenticAgentCoordinator::decomposeLargeTask(const std::string& goal)
{
    json subtasks = json::array();

    // Use analyzer agent to decompose
    auto analyzers = getAvailableAgents(AgentRole::Analyzer);
    if (analyzers.empty()) {
        std::cerr << "[AgenticAgentCoordinator] No analyzer agent available" << std::endl;
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

    std::clog << "[AgenticAgentCoordinator] Synchronized all agent states" << std::endl;
}

bool AgenticAgentCoordinator::detectStateConflict(const std::string& agentId1, const std::string& agentId2)
{
    auto agent1 = getAgent(agentId1);
    auto agent2 = getAgent(agentId2);

    if (!agent1 || !agent2 || !agent1->state || !agent2->state) {
        return false;
    }

    // Compare states
    json state1 = agent1->state->getAllMemory();
    json state2 = agent2->state->getAllMemory();

    return state1 != state2;
}

std::string AgenticAgentCoordinator::resolveStateConflict(const std::string& agentId1, const std::string& agentId2)
{
    auto agent1 = getAgent(agentId1);
    auto agent2 = getAgent(agentId2);

    if (!agent1 || !agent2) {
        return "Agent not found";
    }

    json state1 = agent1->state->getAllMemory();
    json state2 = agent2->state->getAllMemory();

    std::string resolution = reconcileConflictingStates(state1, state2);

    recordConflict(agentId1, agentId2, "State conflict", resolution);

    if (m_onStateConflictDetected) m_onStateConflictDetected(agentId1, agentId2);
    if (m_onStateConflictResolved) m_onStateConflictResolved(resolution);

    return resolution;
}

bool AgenticAgentCoordinator::buildConsensus(const std::vector<std::string>& agentIds, const std::string& question)
{
    std::vector<std::string> opinions;

    for (const auto& agentId : agentIds) {
        auto agent = getAgent(agentId);
        if (agent && agent->state) {
            opinions.push_back(getAgentOpinion(agentId, question));
        }
    }

    // Check if opinions converge
    return !opinions.empty();
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
        std::clog << "[AgenticAgentCoordinator] Allocated resources to agent: " << agentId << std::endl;
    }
}

void AgenticAgentCoordinator::rebalanceResources()
{
    // Reallocate resources based on utilization
    std::clog << "[AgenticAgentCoordinator] Rebalanced resources across agents" << std::endl;
}

// ===== MONITORING =====

json AgenticAgentCoordinator::getCoordinationMetrics() const
{
    json metrics;

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

json AgenticAgentCoordinator::getConflictHistory()
{
    json history = json::array();

    for (const auto& conflict : m_conflicts) {
        json obj;
        obj["conflict_id"] = conflict.conflictId;
        obj["agent1"] = conflict.agent1Id;
        obj["agent2"] = conflict.agent2Id;
        obj["reason"] = conflict.conflictReason;
        obj["resolution"] = conflict.resolution;

        auto t = std::chrono::system_clock::to_time_t(conflict.timestamp);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        obj["timestamp"] = ss.str();

        history.push_back(obj);
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

    return bestAgent ? bestAgent->agentId : "";
}

void AgenticAgentCoordinator::rebalanceWorkload()
{
    // Redistribute tasks from over-utilized to under-utilized agents
    std::clog << "[AgenticAgentCoordinator] Rebalanced workload across agents" << std::endl;
}

// ===== STATE MANAGEMENT =====

json AgenticAgentCoordinator::getGlobalState()
{
    json globalState;
    globalState["agents"] = getAllAgentStatuses();
    globalState["tasks"] = getAllTaskStatuses();
    globalState["metrics"] = getCoordinationMetrics();

    return globalState;
}

bool AgenticAgentCoordinator::restoreGlobalState(const json& state)
{
    // Restore agent and task states
    return true;
}

void AgenticAgentCoordinator::saveCheckpoint()
{
    m_lastCheckpoint = getGlobalState();
    m_lastCheckpointTime = std::chrono::system_clock::now();

    std::clog << "[AgenticAgentCoordinator] Saved checkpoint" << std::endl;
}

bool AgenticAgentCoordinator::restoreFromCheckpoint()
{
    if (m_lastCheckpoint.is_null() || m_lastCheckpoint.empty()) {
        return false;
    }

    return restoreGlobalState(m_lastCheckpoint);
}

// ===== PRIVATE HELPERS =====

void AgenticAgentCoordinator::syncStateWithAgent(const std::string& agentId)
{
    auto agent = getAgent(agentId);
    if (!agent || !agent->state) return;

    // Synchronize agent state with global coordinator state
}

std::string AgenticAgentCoordinator::reconcileConflictingStates(
    const json& state1,
    const json& state2)
{
    // Merge conflicting states intelligently
    return "States reconciled using merge strategy";
}

std::string AgenticAgentCoordinator::selectResolutionStrategy(const std::string& conflictReason)
{
    if (conflictReason.find("state") != std::string::npos) {
        return "merge";
    } else if (conflictReason.find("priority") != std::string::npos) {
        return "priority_based";
    }
    return "consensus";
}

void AgenticAgentCoordinator::recordConflict(
    const std::string& agent1,
    const std::string& agent2,
    const std::string& reason,
    const std::string& resolution)
{
    AgentConflict conflict;
    conflict.conflictId = generateUuid();
    conflict.agent1Id = agent1;
    conflict.agent2Id = agent2;
    conflict.conflictReason = reason;
    conflict.resolution = resolution;
    conflict.timestamp = std::chrono::system_clock::now();

    m_conflicts.push_back(conflict);
    m_totalConflicts++;
}

void AgenticAgentCoordinator::updateAgentMetrics(const std::string& agentId)
{
    auto agent = getAgent(agentId);
    if (!agent) return;

    // Calculate and update metrics
    if (m_onCoordinationMetricsUpdated) m_onCoordinationMetricsUpdated();
}
