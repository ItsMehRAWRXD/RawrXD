/**
 * @file dynamic_planner.cpp
 * @brief Implementation of Dynamic Planner priority-based scheduler
 */

#include "dynamic_planner.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace rawrxd::cognitive {

// ============================================================================
// CapabilityRegistry Implementation
// ============================================================================

void CapabilityRegistry::RegisterCapability(const Capability& cap) {
    std::unique_lock lock(m_mutex);
    m_capabilities[cap.name] = cap;
}

void CapabilityRegistry::UnregisterCapability(const std::string& name) {
    std::unique_lock lock(m_mutex);
    m_capabilities.erase(name);
    
    // Remove from agent mappings
    for (auto& [agent, caps] : m_agent_capabilities) {
        caps.erase(std::remove(caps.begin(), caps.end(), name), caps.end());
    }
    m_capability_agents.erase(name);
}

std::optional<Capability> CapabilityRegistry::GetCapability(const std::string& name) const {
    std::shared_lock lock(m_mutex);
    auto it = m_capabilities.find(name);
    if (it != m_capabilities.end()) return it->second;
    return std::nullopt;
}

std::vector<Capability> CapabilityRegistry::GetAllCapabilities() const {
    std::shared_lock lock(m_mutex);
    std::vector<Capability> result;
    for (const auto& [name, cap] : m_capabilities) {
        result.push_back(cap);
    }
    return result;
}

std::vector<std::string> CapabilityRegistry::FindAgentsForCapability(const std::string& capability_name) const {
    std::shared_lock lock(m_mutex);
    auto it = m_capability_agents.find(capability_name);
    if (it != m_capability_agents.end()) return it->second;
    return {};
}

void CapabilityRegistry::RegisterAgentCapability(const std::string& agent_name, 
                                                  const std::string& capability_name) {
    std::unique_lock lock(m_mutex);
    m_agent_capabilities[agent_name].push_back(capability_name);
    m_capability_agents[capability_name].push_back(agent_name);
}

void CapabilityRegistry::UnregisterAgent(const std::string& agent_name) {
    std::unique_lock lock(m_mutex);
    auto it = m_agent_capabilities.find(agent_name);
    if (it != m_agent_capabilities.end()) {
        for (const auto& cap : it->second) {
            auto cap_it = m_capability_agents.find(cap);
            if (cap_it != m_capability_agents.end()) {
                cap_it->second.erase(
                    std::remove(cap_it->second.begin(), cap_it->second.end(), agent_name),
                    cap_it->second.end());
            }
        }
        m_agent_capabilities.erase(it);
    }
}

// ============================================================================
// DynamicPlanner Implementation
// ============================================================================

DynamicPlanner::DynamicPlanner(EnhancedBlackboard* blackboard)
    : m_blackboard(blackboard)
    , m_capability_registry(std::make_unique<CapabilityRegistry>()) {}

DynamicPlanner::~DynamicPlanner() {
    Stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void DynamicPlanner::Start() {
    if (m_running.exchange(true)) return;
    m_scheduler_thread = std::thread(&DynamicPlanner::SchedulerLoop, this);
}

void DynamicPlanner::Stop() {
    m_running = false;
    m_task_available.notify_all();
    if (m_scheduler_thread.joinable()) {
        m_scheduler_thread.join();
    }
}

// ============================================================================
// Scheduler Loop
// ============================================================================

void DynamicPlanner::SchedulerLoop() {
    while (m_running.load()) {
        std::unique_lock lock(m_mutex);
        
        // Wait for tasks or timeout
        m_task_available.wait_for(lock, std::chrono::seconds(1), [this] {
            return !m_task_queue.empty() || !m_running.load();
        });
        
        if (!m_running.load()) break;
        
        // Prune expired tasks
        PruneExpiredTasks();
        
        // Process runnable tasks up to max concurrency
        while (m_active_tasks.size() < m_max_concurrent_tasks && !m_task_queue.empty()) {
            auto task_opt = GetNextRunnableTask();
            if (!task_opt) break;
            
            Task task = *task_opt;
            m_active_tasks[task.id] = task;
            
            // Find best executor
            auto executor_opt = SelectBestExecutor(task);
            if (executor_opt) {
                auto executor_it = m_executors.find(*executor_opt);
                if (executor_it != m_executors.end()) {
                    lock.unlock();
                    
                    auto start = std::chrono::steady_clock::now();
                    auto result = executor_it->second->Execute(task);
                    auto end = std::chrono::steady_clock::now();
                    result.execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                    
                    SubmitResult(result);
                    
                    lock.lock();
                }
            } else {
                // No executor available, put back in queue
                m_task_queue.push(task);
                break;
            }
        }
    }
}

// ============================================================================
// Mission Scheduling
// ============================================================================

void DynamicPlanner::ScheduleMission(const std::vector<SubGoal>& subgoals) {
    std::unique_lock lock(m_mutex);
    
    for (const auto& sg : subgoals) {
        Task task;
        task.id = sg.id.empty() ? GenerateUUID() : sg.id;
        task.subgoal = sg;
        task.dependencies = sg.dependencies;
        task.priority = sg.priority;
        task.deadline = sg.timeout;
        task.scheduled_time = std::chrono::system_clock::now();
        
        m_task_queue.push(std::move(task));
    }
    
    lock.unlock();
    m_task_available.notify_all();
}

void DynamicPlanner::ScheduleTask(Task&& task) {
    std::unique_lock lock(m_mutex);
    if (task.id.empty()) task.id = GenerateUUID();
    m_task_queue.push(std::move(task));
    lock.unlock();
    m_task_available.notify_all();
}

void DynamicPlanner::ScheduleTasks(const std::vector<Task>& tasks) {
    std::unique_lock lock(m_mutex);
    for (auto task : tasks) {
        if (task.id.empty()) task.id = GenerateUUID();
        m_task_queue.push(std::move(task));
    }
    lock.unlock();
    m_task_available.notify_all();
}

// ============================================================================
// Task Execution
// ============================================================================

std::optional<Task> DynamicPlanner::GetNextRunnableTask() {
    if (m_task_queue.empty()) return std::nullopt;
    
    // Find first task with met dependencies
    std::vector<Task> temp;
    std::optional<Task> result;
    
    while (!m_task_queue.empty() && !result) {
        Task task = m_task_queue.top();
        m_task_queue.pop();
        
        if (AreDependenciesMet(task) && !m_cancelled_tasks.count(task.id)) {
            result = task;
        } else {
            temp.push_back(task);
        }
    }
    
    // Put back non-runnable tasks
    for (auto& t : temp) {
        m_task_queue.push(std::move(t));
    }
    
    return result;
}

void DynamicPlanner::SubmitResult(const ExecutionResult& result) {
    std::unique_lock lock(m_mutex);
    
    auto it = m_active_tasks.find(result.task_id);
    if (it == m_active_tasks.end()) return;
    
    Task task = it->second;
    m_active_tasks.erase(it);
    
    if (result.success) {
        task.completed = true;
        m_completed_tasks[task.id] = task;
        
        // Record evidence
        for (const auto& ev_id : result.evidence_produced) {
            task.subgoal.evidence_ids.push_back(ev_id);
        }
        
        // Update blackboard
        m_blackboard->MarkTaskComplete(task.id, result.outputs);
        
        // Record agent success
        if (!result.agent_name.empty()) {
            float confidence = 0.0f;
            for (const auto& [key, val] : result.outputs) {
                confidence += val;
            }
            if (!result.outputs.empty()) confidence /= result.outputs.size();
            
            m_blackboard->RecordAgentSuccess(result.agent_name, "", confidence, 
                                               static_cast<float>(result.execution_time.count()));
        }
    } else {
        task.failed = true;
        task.failure_reason = result.error_message;
        m_failed_tasks[task.id] = task;
        
        m_blackboard->MarkTaskFailed(task.id, result.error_message);
        
        // Record agent failure
        if (!result.agent_name.empty()) {
            m_blackboard->RecordAgentFailure(result.agent_name, "", result.error_message);
        }
    }
}

void DynamicPlanner::CancelTask(const std::string& task_id) {
    std::unique_lock lock(m_mutex);
    m_cancelled_tasks.insert(task_id);
    
    // Remove from active tasks
    auto active_it = m_active_tasks.find(task_id);
    if (active_it != m_active_tasks.end()) {
        m_active_tasks.erase(active_it);
    }
}

void DynamicPlanner::CancelAllTasks() {
    std::unique_lock lock(m_mutex);
    
    // Cancel all pending tasks
    auto tasks = DrainQueue();
    for (const auto& task : tasks) {
        m_cancelled_tasks.insert(task.id);
    }
    
    // Cancel all active tasks
    for (const auto& [id, task] : m_active_tasks) {
        m_cancelled_tasks.insert(id);
    }
    m_active_tasks.clear();
}

// ============================================================================
// Replanning
// ============================================================================

void DynamicPlanner::Replan(const std::vector<SubGoal>& updated_subgoals) {
    std::unique_lock lock(m_mutex);
    
    // Drain existing queue
    auto existing_tasks = DrainQueue();
    
    // Build set of updated task IDs
    std::unordered_set<std::string> updated_ids;
    for (const auto& sg : updated_subgoals) {
        updated_ids.insert(sg.id);
    }
    
    // Keep tasks that aren't being updated
    for (auto& task : existing_tasks) {
        if (!updated_ids.count(task.id)) {
            m_task_queue.push(std::move(task));
        }
    }
    
    // Add updated subgoals as new tasks
    for (const auto& sg : updated_subgoals) {
        Task task;
        task.id = sg.id;
        task.subgoal = sg;
        task.dependencies = sg.dependencies;
        task.priority = sg.priority;
        task.deadline = sg.timeout;
        task.scheduled_time = std::chrono::system_clock::now();
        m_task_queue.push(std::move(task));
    }
    
    lock.unlock();
    m_task_available.notify_all();
}

void DynamicPlanner::InjectTasks(const std::vector<Task>& new_tasks, 
                                  const std::string& after_task_id) {
    std::unique_lock lock(m_mutex);
    
    for (const auto& new_task : new_tasks) {
        Task task = new_task;
        if (task.id.empty()) task.id = GenerateUUID();
        if (!after_task_id.empty()) {
            task.dependencies.push_back(after_task_id);
        }
        m_task_queue.push(std::move(task));
    }
    
    lock.unlock();
    m_task_available.notify_all();
}

void DynamicPlanner::BoostPriority(const std::string& task_id, int boost) {
    std::unique_lock lock(m_mutex);
    
    // Need to rebuild queue to change priority
    auto tasks = DrainQueue();
    for (auto& task : tasks) {
        if (task.id == task_id) {
            task.priority = std::min(task.priority + boost, 100);
        }
        m_task_queue.push(std::move(task));
    }
}

void DynamicPlanner::PenalizePriority(const std::string& task_id, int penalty) {
    std::unique_lock lock(m_mutex);
    
    auto tasks = DrainQueue();
    for (auto& task : tasks) {
        if (task.id == task_id) {
            task.priority = std::max(task.priority - penalty, 0);
        }
        m_task_queue.push(std::move(task));
    }
}

// ============================================================================
// Agent Management
// ============================================================================

void DynamicPlanner::RegisterExecutor(const std::string& name, 
                                       std::shared_ptr<ITaskExecutor> executor) {
    std::unique_lock lock(m_mutex);
    m_executors[name] = executor;
    
    // Register capabilities
    for (const auto& cap : executor->GetCapabilities()) {
        m_capability_registry->RegisterAgentCapability(name, cap);
    }
}

void DynamicPlanner::UnregisterExecutor(const std::string& name) {
    std::unique_lock lock(m_mutex);
    m_executors.erase(name);
    m_capability_registry->UnregisterAgent(name);
}

std::vector<std::string> DynamicPlanner::FindCapableExecutors(const Task& task) const {
    std::shared_lock lock(m_mutex);
    std::vector<std::string> capable;
    
    for (const auto& req_cap : task.subgoal.required_capabilities) {
        auto agents = m_capability_registry->FindAgentsForCapability(req_cap);
        for (const auto& agent : agents) {
            auto exec_it = m_executors.find(agent);
            if (exec_it != m_executors.end() && exec_it->second->CanExecute(task)) {
                if (std::find(capable.begin(), capable.end(), agent) == capable.end()) {
                    capable.push_back(agent);
                }
            }
        }
    }
    
    return capable;
}

std::optional<std::string> DynamicPlanner::SelectBestExecutor(const Task& task) const {
    auto capable = FindCapableExecutors(task);
    if (capable.empty()) return std::nullopt;
    
    // Select based on historical performance
    std::string best_executor;
    float best_score = -1.0f;
    
    for (const auto& agent : capable) {
        auto perf = m_blackboard->GetAgentPerformance(agent);
        float score = perf ? perf->SuccessRate() : 0.5f;
        
        if (score > best_score) {
            best_score = score;
            best_executor = agent;
        }
    }
    
    return best_executor.empty() ? std::nullopt : std::optional<std::string>(best_executor);
}

// ============================================================================
// Status
// ============================================================================

bool DynamicPlanner::HasPendingTasks() const {
    std::shared_lock lock(m_mutex);
    return !m_task_queue.empty();
}

bool DynamicPlanner::HasRunnableTasks() {
    std::unique_lock lock(m_mutex);
    
    auto tasks = DrainQueue();
    bool has_runnable = false;
    
    for (const auto& task : tasks) {
        if (AreDependenciesMet(task) && !m_cancelled_tasks.count(task.id)) {
            has_runnable = true;
        }
        m_task_queue.push(task);
    }
    
    return has_runnable;
}

size_t DynamicPlanner::PendingTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_task_queue.size();
}

size_t DynamicPlanner::ActiveTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_active_tasks.size();
}

size_t DynamicPlanner::CompletedTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_completed_tasks.size();
}

size_t DynamicPlanner::FailedTaskCount() const {
    std::shared_lock lock(m_mutex);
    return m_failed_tasks.size();
}

float DynamicPlanner::MissionProgress() const {
    std::shared_lock lock(m_mutex);
    
    size_t total = m_completed_tasks.size() + m_failed_tasks.size() + m_task_queue.size() + m_active_tasks.size();
    if (total == 0) return 0.0f;
    
    return static_cast<float>(m_completed_tasks.size()) / static_cast<float>(total);
}

// ============================================================================
// Utility
// ============================================================================

std::vector<Task> DynamicPlanner::GetTaskQueueSnapshot() const {
    std::shared_lock lock(m_mutex);
    
    std::vector<Task> result;
    auto queue_copy = m_task_queue;
    while (!queue_copy.empty()) {
        result.push_back(queue_copy.top());
        queue_copy.pop();
    }
    return result;
}

std::string DynamicPlanner::GenerateScheduleReport() const {
    std::shared_lock lock(m_mutex);
    std::ostringstream oss;
    
    oss << "=== DynamicPlanner Schedule Report ===\n";
    oss << "Pending Tasks: " << m_task_queue.size() << "\n";
    oss << "Active Tasks: " << m_active_tasks.size() << "\n";
    oss << "Completed Tasks: " << m_completed_tasks.size() << "\n";
    oss << "Failed Tasks: " << m_failed_tasks.size() << "\n";
    float progress = MissionProgress() * 100.0f;
    oss << "Progress: " << std::fixed << std::setprecision(1) << progress << "%\n";
    
    if (!m_active_tasks.empty()) {
        oss << "\nActive Tasks:\n";
        for (const auto& [id, task] : m_active_tasks) {
            oss << "  " << id << ": " << task.subgoal.description.substr(0, 40);
            if (task.subgoal.description.length() > 40) oss << "...";
            oss << " (pri: " << task.priority << ")\n";
        }
    }
    
    return oss.str();
}

void DynamicPlanner::WaitForCompletion() {
    while (m_running.load()) {
        {
            std::shared_lock lock(m_mutex);
            if (m_task_queue.empty() && m_active_tasks.empty()) {
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

bool DynamicPlanner::AreDependenciesMet(const Task& task) const {
    for (const auto& dep : task.dependencies) {
        if (m_completed_tasks.find(dep) == m_completed_tasks.end()) {
            return false;
        }
    }
    return true;
}

bool DynamicPlanner::IsTaskExpired(const Task& task) const {
    return task.IsExpired();
}

void DynamicPlanner::PruneExpiredTasks() {
    std::vector<Task> temp;
    
    while (!m_task_queue.empty()) {
        Task task = m_task_queue.top();
        m_task_queue.pop();
        
        if (!IsTaskExpired(task) && !m_cancelled_tasks.count(task.id)) {
            temp.push_back(task);
        }
    }
    
    for (auto& t : temp) {
        m_task_queue.push(std::move(t));
    }
}

void DynamicPlanner::RecalculateAllPriorities() {
    // Recalculate task priorities based on current system state
    // This implementation maintains existing priorities but provides
    // the foundation for dynamic priority adjustment based on:
    //   - System load and resource availability
    //   - Task dependencies and critical path analysis
    //   - Deadline proximity and urgency
    //   - Historical execution patterns
    
    std::vector<Task> tasks = DrainQueue();
    for (auto& task : tasks) {
        task.priority = ComputeTaskPriority(task);
    }
    
    // Re-sort queue by updated priorities
    for (auto& t : tasks) {
        m_task_queue.push(std::move(t));
    }
}

int DynamicPlanner::ComputeTaskPriority(const Task& task) const {
    int priority = task.priority;
    
    // Boost priority for tasks on critical path (many dependents)
    // This is a simplified version
    
    return priority;
}

void DynamicPlanner::RebuildQueue() {
    auto tasks = DrainQueue();
    for (auto& task : tasks) {
        m_task_queue.push(std::move(task));
    }
}

std::vector<Task> DynamicPlanner::DrainQueue() {
    std::vector<Task> result;
    while (!m_task_queue.empty()) {
        result.push_back(m_task_queue.top());
        m_task_queue.pop();
    }
    return result;
}

} // namespace rawrxd::cognitive
