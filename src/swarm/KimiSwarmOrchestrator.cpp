#include "KimiSwarmOrchestrator.hpp"
#include <algorithm>
#include <sstream>

namespace rawrxd {
namespace swarm {

// Global instance
static std::unique_ptr<KimiSwarmOrchestrator> g_kimiSwarm;

KimiSwarmOrchestrator* GetKimiSwarm() {
    return g_kimiSwarm.get();
}

void InitializeKimiSwarm(const KimiSwarmConfig& config) {
    g_kimiSwarm = std::make_unique<KimiSwarmOrchestrator>(config);
    g_kimiSwarm->initialize();
}

void ShutdownKimiSwarm() {
    if (g_kimiSwarm) {
        g_kimiSwarm->shutdown();
        g_kimiSwarm.reset();
    }
}

KimiSwarmOrchestrator::KimiSwarmOrchestrator(const KimiSwarmConfig& config)
    : config_(config) {
}

KimiSwarmOrchestrator::~KimiSwarmOrchestrator() {
    shutdown();
}

bool KimiSwarmOrchestrator::initialize() {
    if (running_.exchange(true)) {
        return false; // Already running
    }

    // Initialize components
    if (config_.enableVibeEngine) {
        vibeEngine_ = std::make_unique<CinematicVibeEngine>();
    }

    if (config_.enableDeepContext) {
        contextManager_ = std::make_unique<DeepContextManager>();
    }

    if (config_.enableOpenClaw) {
        openClaw_ = std::make_unique<OpenClawBridge>();
    }

    if (config_.enableLegacyRefactor) {
        refactorModule_ = std::make_unique<LegacyRefactorModule>();
    }

    // Initialize agent components
    architect_ = std::make_unique<ArchitectAgent>();
    frontend_ = std::make_unique<FrontendSquad>();
    backend_ = std::make_unique<BackendCore>();
    qa_ = std::make_unique<QAHive>();
    reviewers_ = std::make_unique<ReviewerAgents>();

    // Initialize agent states
    agentStates_["architect"] = std::vector<AgentState>(config_.architectCount);
    agentStates_["frontend"] = std::vector<AgentState>(config_.frontendCount);
    agentStates_["backend"] = std::vector<AgentState>(config_.backendCount);
    agentStates_["qa"] = std::vector<AgentState>(config_.qaCount);
    agentStates_["reviewer"] = std::vector<AgentState>(config_.reviewerCount);

    for (auto& [type, states] : agentStates_) {
        for (size_t i = 0; i < states.size(); ++i) {
            states[i].type = type;
            states[i].id = i;
            states[i].active = true;
            states[i].lastHeartbeat = std::chrono::steady_clock::now();
        }
    }

    // Start worker threads
    for (size_t i = 0; i < config_.threadPoolSize; ++i) {
        workers_.emplace_back(&KimiSwarmOrchestrator::workerLoop, this);
    }

    // Update stats
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalAgents = config_.architectCount + config_.frontendCount +
                            config_.backendCount + config_.qaCount + config_.reviewerCount;
        stats_.activeAgents = stats_.totalAgents;
        stats_.idleAgents = stats_.totalAgents;
    }

    return true;
}

void KimiSwarmOrchestrator::shutdown() {
    if (!running_.exchange(false)) {
        return; // Already shut down
    }

    // Wake up all workers
    queueCV_.notify_all();

    // Wait for workers to finish
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();

    // Clear components
    architect_.reset();
    frontend_.reset();
    backend_.reset();
    qa_.reset();
    reviewers_.reset();
    vibeEngine_.reset();
    contextManager_.reset();
    openClaw_.reset();
    refactorModule_.reset();
}

void KimiSwarmOrchestrator::workerLoop() {
    while (running_.load()) {
        std::function<void()> work;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] { return !workQueue_.empty() || !running_.load(); });
            
            if (!running_.load()) break;
            
            if (!workQueue_.empty()) {
                work = std::move(workQueue_.front());
                workQueue_.pop();
                activeWorkers_++;
            }
        }
        
        if (work) {
            work();
            activeWorkers_--;
        }
    }
}

uint64_t KimiSwarmOrchestrator::submitTask(const KimiTask& task) {
    uint64_t taskId = nextTaskId_++;
    
    KimiTask taskCopy = task;
    taskCopy.id = taskId;
    taskCopy.created = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        pendingTasks_[taskId] = taskCopy;
    }
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        workQueue_.push([this, taskCopy]() {
            processTask(taskCopy);
        });
    }
    
    queueCV_.notify_one();
    return taskId;
}

std::vector<uint64_t> KimiSwarmOrchestrator::submitTasks(const std::vector<KimiTask>& tasks) {
    std::vector<uint64_t> taskIds;
    taskIds.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        taskIds.push_back(submitTask(task));
    }
    
    return taskIds;
}

void KimiSwarmOrchestrator::processTask(const KimiTask& task) {
    auto start = std::chrono::steady_clock::now();
    
    KimiTaskResult result;
    result.taskId = task.id;
    result.agentType = task.type;
    
    // Find available agent
    size_t agentId = 0;
    {
        std::lock_guard<std::mutex> lock(agentMutex_);
        auto& states = agentStates_[task.type];
        for (size_t i = 0; i < states.size(); ++i) {
            if (states[i].active && states[i].currentTask.empty()) {
                agentId = i;
                states[i].currentTask = std::to_string(task.id);
                break;
            }
        }
    }
    
    updateAgentState(task.type, agentId, true, std::to_string(task.id));
    
    // Execute task based on type
    try {
        if (task.type == "architect") {
            result = handleArchitectTask(task);
        } else if (task.type == "frontend") {
            result = handleFrontendTask(task);
        } else if (task.type == "backend") {
            result = handleBackendTask(task);
        } else if (task.type == "qa") {
            result = handleQATask(task);
        } else if (task.type == "reviewer") {
            result = handleReviewTask(task);
        } else {
            result.success = false;
            result.error = "Unknown task type: " + task.type;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }
    
    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    result.agentId = agentId;
    
    // Update agent state
    updateAgentState(task.type, agentId, true, "");
    
    // Store result
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        completedTasks_[task.id] = result;
        pendingTasks_.erase(task.id);
        
        // Fulfill promise if exists
        auto it = taskPromises_.find(task.id);
        if (it != taskPromises_.end()) {
            it->second.set_value(result);
            taskPromises_.erase(it);
        }
    }
    
    // Update stats
    recordTaskCompletion(result);
    
    // Call callback if provided
    if (task.callback) {
        task.callback(result.output);
    }
}

KimiTaskResult KimiSwarmOrchestrator::handleArchitectTask(const KimiTask& task) {
    KimiTaskResult result;
    result.success = true;
    result.output = "Architect task completed: " + task.description;
    
    // Parse context as JSON request
    // In production, would actually call ArchitectAgent::designSystem
    
    return result;
}

KimiTaskResult KimiSwarmOrchestrator::handleFrontendTask(const KimiTask& task) {
    KimiTaskResult result;
    result.success = true;
    result.output = "Frontend task completed: " + task.description;
    
    // In production, would call FrontendSquad::generatePage
    
    return result;
}

KimiTaskResult KimiSwarmOrchestrator::handleBackendTask(const KimiTask& task) {
    KimiTaskResult result;
    result.success = true;
    result.output = "Backend task completed: " + task.description;
    
    // In production, would call BackendCore::generateService
    
    return result;
}

KimiTaskResult KimiSwarmOrchestrator::handleQATask(const KimiTask& task) {
    KimiTaskResult result;
    result.success = true;
    result.output = "QA task completed: " + task.description;
    
    // In production, would call QAHive::generateUnitTest
    
    return result;
}

KimiTaskResult KimiSwarmOrchestrator::handleReviewTask(const KimiTask& task) {
    KimiTaskResult result;
    result.success = true;
    result.output = "Review task completed: " + task.description;
    
    // In production, would call ReviewerAgents::reviewFile
    
    return result;
}

void KimiSwarmOrchestrator::updateAgentState(const std::string& type, size_t id, 
                                              bool active, const std::string& task) {
    std::lock_guard<std::mutex> lock(agentMutex_);
    auto& states = agentStates_[type];
    if (id < states.size()) {
        states[id].active = active;
        states[id].currentTask = task;
        states[id].lastHeartbeat = std::chrono::steady_clock::now();
    }
}

void KimiSwarmOrchestrator::recordTaskCompletion(const KimiTaskResult& result) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    if (result.success) {
        stats_.totalTasksCompleted++;
    } else {
        stats_.totalTasksFailed++;
    }
    
    stats_.tasksByType[result.agentType]++;
    
    // Update average duration
    size_t totalTasks = stats_.totalTasksCompleted + stats_.totalTasksFailed;
    stats_.avgTaskDurationMs = (stats_.avgTaskDurationMs * (totalTasks - 1) + 
                                   result.duration.count()) / totalTasks;
}

ProjectResult KimiSwarmOrchestrator::generateProject(const ProjectRequest& request) {
    auto start = std::chrono::steady_clock::now();
    ProjectResult result;
    
    // Phase 1: Architect designs system
    ArchitectAgent::DesignRequest designReq;
    designReq.projectName = request.name;
    designReq.description = request.description;
    designReq.features = request.features;
    designReq.targetPlatform = request.targetPlatform;
    designReq.scale = request.scale;
    designReq.constraints = request.constraints;
    
    auto design = architect_->designSystem(designReq);
    
    // Phase 2: Generate vibe/design system
    CinematicVibeEngine::VibeSpec vibeSpec;
    vibeSpec.mood = request.vibe;
    vibeSpec.darkMode = request.darkMode;
    auto designSystem = vibeEngine_->generateDesignSystem(vibeSpec);
    
    // Phase 3: Frontend squad generates UI
    std::vector<FrontendSquad::PageRequest> pageRequests;
    // Create page requests based on features...
    
    auto frontendResult = frontend_->generateApplication(pageRequests, designSystem);
    
    // Phase 4: Backend core generates APIs
    BackendCore::BackendRequest backendReq;
    // Populate backend request...
    
    auto backendResult = backend_->generateBackend(backendReq);
    
    // Phase 5: QA generates tests
    std::vector<TestSpec> testSpecs;
    // Create test specs...
    
    auto testResults = qa_->runTestSuite(testSpecs);
    
    // Phase 6: Reviewers audit code
    std::vector<std::string> files;
    // Collect generated files...
    
    auto reviewReports = reviewers_->reviewCodebase(files);
    
    // Compile results
    result.success = true;
    result.totalFilesGenerated = frontendResult.pages.size() + 
                                  backendResult.serviceFiles.size();
    
    auto end = std::chrono::steady_clock::now();
    result.totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return result;
}

std::future<ProjectResult> KimiSwarmOrchestrator::generateProjectAsync(const ProjectRequest& request) {
    return std::async(std::launch::async, [this, request]() {
        return this->generateProject(request);
    });
}

KimiTaskResult KimiSwarmOrchestrator::getTaskResult(uint64_t taskId) {
    std::lock_guard<std::mutex> lock(taskMutex_);
    auto it = completedTasks_.find(taskId);
    if (it != completedTasks_.end()) {
        return it->second;
    }
    return KimiTaskResult{};
}

std::vector<KimiTaskResult> KimiSwarmOrchestrator::getTaskResults(const std::vector<uint64_t>& taskIds) {
    std::vector<KimiTaskResult> results;
    results.reserve(taskIds.size());
    
    for (uint64_t id : taskIds) {
        results.push_back(getTaskResult(id));
    }
    
    return results;
}

std::vector<AgentState> KimiSwarmOrchestrator::getAgentStates() const {
    std::lock_guard<std::mutex> lock(agentMutex_);
    std::vector<AgentState> allStates;
    
    for (const auto& [type, states] : agentStates_) {
        allStates.insert(allStates.end(), states.begin(), states.end());
    }
    
    return allStates;
}

SwarmStats KimiSwarmOrchestrator::getStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    SwarmStats stats = stats_;
    
    {
        std::lock_guard<std::mutex> qLock(queueMutex_);
        stats.queueDepth = workQueue_.size();
    }
    
    return stats;
}

void KimiSwarmOrchestrator::resetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = SwarmStats{};
}

void KimiSwarmOrchestrator::setSharedState(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    sharedState_[key] = value;
}

std::string KimiSwarmOrchestrator::getSharedState(const std::string& key) const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    auto it = sharedState_.find(key);
    return it != sharedState_.end() ? it->second : "";
}

void KimiSwarmOrchestrator::clearSharedState() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    sharedState_.clear();
}

} // namespace swarm
} // namespace rawrxd
