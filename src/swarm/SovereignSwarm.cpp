#include "SovereignSwarm.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Sovereign {

// Initialize default role models from your Ollama roster
void SwarmAgentContext::InitializeDefaultRoleModels() {
    // Scanner: Nemotron-3 Super (86GB) - broad understanding for scanning
    roleModels[ModelRole::Scanner] = {
        "nemotron-super:latest",
        "models/nemotron-super-86b.gguf",
        "Q4_K_M",
        32768,
        0.7f,
        0.9f,
        40,
        {"scan", "detect", "analyze"}
    };
    
    // Repairer: Qwen 3.5 40B - precise for repairs
    roleModels[ModelRole::Repairer] = {
        "qwen3.5:40b",
        "models/qwen3.5-40b.gguf",
        "Q4_K_M",
        32768,
        0.3f,  // Lower temp for precision
        0.85f,
        20,
        {"repair", "fix", "correct"}
    };
    
    // Extender: Codestral 22B - creative for extensions
    roleModels[ModelRole::Extender] = {
        "codestral:22b",
        "models/codestral-22b.gguf",
        "Q4_K_M",
        32768,
        0.8f,  // Higher temp for creativity
        0.95f,
        50,
        {"extend", "generate", "create"}
    };
    
    // Optimizer: DeepSeek R1 8B - fast for optimization
    roleModels[ModelRole::Optimizer] = {
        "deepseek-r1:8b",
        "models/deepseek-r1-8b.gguf",
        "Q8_0",
        16384,
        0.5f,
        0.9f,
        30,
        {"optimize", "improve", "refactor"}
    };
    
    // Harmonizer: Gemma 3 27B - balanced for harmonization
    roleModels[ModelRole::Harmonizer] = {
        "gemma3:27b",
        "models/gemma3-27b.gguf",
        "Q4_K_M",
        32768,
        0.6f,
        0.88f,
        35,
        {"harmonize", "balance", "unify"}
    };
    
    // Finalizer: BigDaddyG 38GB - powerful for finalization
    roleModels[ModelRole::Finalizer] = {
        "bigdaddyg:38gb",
        "models/bigdaddyg-38b.gguf",
        "Q4_K_M",
        65536,
        0.4f,  // Lower temp for finalization
        0.85f,
        25,
        {"finalize", "complete", "integrate"}
    };
    
    // General fallback: Llama 3.2 3B - lightweight
    roleModels[ModelRole::General] = {
        "llama3.2:3b",
        "models/llama3.2-3b.gguf",
        "Q8_0",
        8192,
        0.7f,
        0.9f,
        40,
        {"general", "fallback", "utility"}
    };
}

void SwarmAgentContext::SetRoleModel(ModelRole role, const RoleModelConfig& config) {
    roleModels[role] = config;
}

RoleModelConfig SwarmAgentContext::GetRoleModel(ModelRole role) const {
    auto it = roleModels.find(role);
    if (it != roleModels.end()) {
        return it->second;
    }
    // Return general fallback
    return roleModels.at(ModelRole::General);
}

std::string SwarmAgentContext::SelectModelForRole(ModelRole role, const std::string& target) {
    auto config = GetRoleModel(role);
    
    // Check if model is available in registry
    if (registry && !registry->IsModelAvailable(config.modelName)) {
        // Fall back to general model
        config = GetRoleModel(ModelRole::General);
    }
    
    return config.modelName;
}

// SwarmAgent implementation
SwarmAgent::SwarmAgent(const SwarmAgentContext& ctx, uint32_t agentId)
    : ctx_(ctx), agentId_(agentId) {}

SwarmTaskResult SwarmAgent::Execute(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.modelUsed = currentModel_;
    
    auto startTime = std::chrono::steady_clock::now();
    
    switch (task.kind) {
        case SwarmTaskKind::ScanSubsystem:
            result = HandleScan(task);
            break;
        case SwarmTaskKind::RepairSubsystem:
            result = HandleRepair(task);
            break;
        case SwarmTaskKind::ExtendSubsystem:
            result = HandleExtend(task);
            break;
        case SwarmTaskKind::OptimizeSubsystem:
            result = HandleOptimize(task);
            break;
        case SwarmTaskKind::HarmonizeCycle:
            result = HandleHarmonize(task);
            break;
        case SwarmTaskKind::FinalizeRuntime:
            result = HandleFinalize(task);
            break;
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    return result;
}

std::vector<SwarmTaskResult> SwarmAgent::ExecuteBatch(const std::vector<SwarmTask>& tasks) {
    std::vector<SwarmTaskResult> results;
    results.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        results.push_back(Execute(task));
    }
    
    return results;
}

SwarmTaskResult SwarmAgent::HandleScan(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    // Select model for scanning role
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Scanner, task.target);
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Scanner, task.target)) {
        result.success = false;
        result.message = "Failed to load scanner model: " + modelName;
        return result;
    }
    
    // Build scan prompt
    std::string prompt = BuildScanPrompt(task.target);
    
    // Run inference
    std::string inferenceResult = RunInference(prompt, modelName);
    
    result.message = "Scanned " + task.target + " with " + modelName + 
                     ", found " + std::to_string(inferenceResult.size()) + " bytes of analysis";
    result.confidence = 0.85f;
    
    // Pass results to CLI for processing
    if (ctx_.cli) {
        ctx_.cli->ScanSubsystem(task.target);
    }
    
    return result;
}

SwarmTaskResult SwarmAgent::HandleRepair(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Repairer, task.target);
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Repairer, task.target)) {
        result.success = false;
        result.message = "Failed to load repairer model: " + modelName;
        return result;
    }
    
    // Detect issues
    std::vector<std::string> issues;
    if (ctx_.cli) {
        issues = ctx_.cli->DetectSubsystemIssues(task.target);
    }
    
    int repairsApplied = 0;
    for (const auto& issue : issues) {
        std::string fixPrompt = BuildRepairPrompt(task.target, issue);
        std::string fixCode = RunInference(fixPrompt, modelName);
        
        if (ctx_.cli) {
            ctx_.cli->ApplyFix(task.target, issue, fixCode);
        }
        repairsApplied++;
    }
    
    result.message = "Repaired " + std::to_string(repairsApplied) + " issues in " + task.target + 
                     " using " + modelName;
    result.confidence = 0.90f;
    
    return result;
}

SwarmTaskResult SwarmAgent::HandleExtend(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Extender, task.target);
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Extender, task.target)) {
        result.success = false;
        result.message = "Failed to load extender model: " + modelName;
        return result;
    }
    
    std::string prompt = BuildExtendPrompt(task.target);
    std::string extensionCode = RunInference(prompt, modelName);
    
    if (ctx_.cli) {
        ctx_.cli->ApplyExtension(task.target, extensionCode);
    }
    
    result.message = "Extended " + task.target + " with " + std::to_string(extensionCode.size()) + 
                     " bytes using " + modelName;
    result.confidence = 0.80f;
    
    return result;
}

SwarmTaskResult SwarmAgent::HandleOptimize(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Optimizer, task.target);
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Optimizer, task.target)) {
        result.success = false;
        result.message = "Failed to load optimizer model: " + modelName;
        return result;
    }
    
    // Find hot paths
    std::vector<std::string> hotPaths;
    if (ctx_.seg) {
        hotPaths = ctx_.seg->FindHotPaths(task.target);
    }
    
    int optimizationsApplied = 0;
    for (const auto& path : hotPaths) {
        std::string optPrompt = BuildOptimizePrompt(task.target, path);
        std::string optCode = RunInference(optPrompt, modelName);
        
        if (ctx_.seg) {
            ctx_.seg->ApplyOptimization(path, optCode);
        }
        optimizationsApplied++;
    }
    
    result.message = "Optimized " + std::to_string(optimizationsApplied) + " hot paths in " + 
                     task.target + " using " + modelName;
    result.confidence = 0.88f;
    
    return result;
}

SwarmTaskResult SwarmAgent::HandleHarmonize(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Harmonizer, "Unity");
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Harmonizer, "Unity")) {
        result.success = false;
        result.message = "Failed to load harmonizer model: " + modelName;
        return result;
    }
    
    // Run the Unity Cycle
    if (ctx_.engine) {
        ctx_.engine->RunUnityCycle(task.cycleId);
    }
    
    // Complete the cycle
    if (ctx_.cli) {
        ctx_.cli->RunUnityCompletionCycle();
    }
    
    result.message = "Harmonized Unity Cycle " + std::to_string(task.cycleId) + " using " + modelName;
    result.confidence = 0.95f;
    
    return result;
}

SwarmTaskResult SwarmAgent::HandleFinalize(const SwarmTask& task) {
    SwarmTaskResult result;
    result.taskId = task.id;
    result.success = true;
    
    std::string modelName = ctx_.SelectModelForRole(ModelRole::Finalizer, "SovereignRuntime");
    result.modelUsed = modelName;
    
    if (!LoadModelForRole(ModelRole::Finalizer, "SovereignRuntime")) {
        result.success = false;
        result.message = "Failed to load finalizer model: " + modelName;
        return result;
    }
    
    // Run totality completion
    if (ctx_.cli && ctx_.engine && ctx_.backend && ctx_.registry) {
        ctx_.cli->RunTotalityCompletionCycle(*ctx_.engine, *ctx_.backend, *ctx_.registry);
    }
    
    // Run autogenesis
    if (ctx_.cli) {
        ctx_.cli->RunAutogenesisCycle();
    }
    
    // Run evolution
    if (ctx_.cli) {
        ctx_.cli->RunEvolutionCycle();
    }
    
    result.message = "Finalized SovereignRuntime using " + modelName;
    result.confidence = 0.98f;
    
    return result;
}

bool SwarmAgent::LoadModelForRole(ModelRole role, const std::string& target) {
    std::string modelName = ctx_.SelectModelForRole(role, target);
    return LoadModelByName(modelName);
}

bool SwarmAgent::LoadModelByName(const std::string& modelName) {
    if (ctx_.backend && ctx_.registry) {
        auto modelInfo = ctx_.registry->GetModelInfo(modelName);
        if (modelInfo.available) {
            ctx_.backend->LoadModel(modelInfo.path);
            currentModel_ = modelName;
            return true;
        }
    }
    return false;
}

void SwarmAgent::UnloadCurrentModel() {
    currentModel_.clear();
}

std::string SwarmAgent::BuildScanPrompt(const std::string& target) {
    return "Scan the " + target + " subsystem for missing components, "
           "incomplete implementations, broken bindings, and optimization opportunities. "
           "Return a detailed report of all issues found.";
}

std::string SwarmAgent::BuildRepairPrompt(const std::string& target, const std::string& issue) {
    return "Repair the following issue in the " + target + 
           " subsystem: " + issue + 
           ". Provide the exact code fix needed.";
}

std::string SwarmAgent::BuildExtendPrompt(const std::string& target) {
    return "Extend the " + target + " subsystem with new functionality. "
           "Consider: Unity Cycle integration, SEG node generation, "
           "OS substrate hooks, agentic surfaces, and telemetry integration. "
           "Generate the complete implementation code.";
}

std::string SwarmAgent::BuildOptimizePrompt(const std::string& target, const std::string& path) {
    return "Optimize the hot path '" + path + "' in the " + 
           target + " subsystem. Focus on: "
           "performance, memory efficiency, and parallelization. "
           "Provide the optimized code.";
}

std::string SwarmAgent::RunInference(const std::string& prompt, const std::string& modelName) {
    if (ctx_.backend) {
        auto config = ctx_.GetRoleModel(ModelRole::General);
        
        // Find the role for this model to get its config
        for (const auto& [role, cfg] : ctx_.roleModels) {
            if (cfg.modelName == modelName) {
                config = cfg;
                break;
            }
        }
        
        return ctx_.backend->RunInference(prompt, modelName, config.temperature, config.contextLength);
    }
    return "";
}

// SwarmScheduler implementation
SwarmScheduler::SwarmScheduler(const SwarmAgentContext& ctx, uint32_t workerCount)
    : ctx_(ctx)
    , workerCount_(workerCount)
    , running_(false)
    , nextId_(1)
    , completedCount_(0)
    , failedCount_(0) {}

SwarmScheduler::~SwarmScheduler() {
    Stop();
}

void SwarmScheduler::Start() {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (running_) return;
        running_ = true;
    }
    
    // Spawn worker threads
    for (uint32_t i = 0; i < workerCount_; ++i) {
        workers_.emplace_back(&SwarmScheduler::WorkerLoop, this, i);
    }
}

void SwarmScheduler::Stop() {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (!running_) return;
        running_ = false;
    }
    queueCv_.notify_all();
    
    // Join all workers
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

uint64_t SwarmScheduler::Enqueue(const SwarmTask& task) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    SwarmTask newTask = task;
    newTask.id = nextId_++;
    
    queue_.push(newTask);
    queueCv_.notify_one();
    
    return newTask.id;
}

std::vector<uint64_t> SwarmScheduler::EnqueueBatch(const std::vector<SwarmTask>& tasks) {
    std::vector<uint64_t> ids;
    ids.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        ids.push_back(Enqueue(task));
    }
    
    return ids;
}

void SwarmScheduler::WaitForCompletion() {
    while (GetPendingCount() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool SwarmScheduler::WaitForCompletionWithTimeout(int64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    while (GetPendingCount() > 0) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeoutMs) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
}

std::vector<SwarmTaskResult> SwarmScheduler::GetResults() const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    std::vector<SwarmTaskResult> results;
    results.reserve(results_.size());
    for (const auto& [id, result] : results_) {
        results.push_back(result);
    }
    return results;
}

SwarmTaskResult SwarmScheduler::GetResult(uint64_t taskId) const {
    std::lock_guard<std::mutex> lock(resultsMutex_);
    auto it = results_.find(taskId);
    if (it != results_.end()) {
        return it->second;
    }
    return SwarmTaskResult{};
}

void SwarmScheduler::EnqueueGlobalCompletionTasks() {
    std::vector<SwarmTask> tasks;
    BuildGlobalTaskList(tasks);
    
    for (const auto& task : tasks) {
        Enqueue(task);
    }
}

size_t SwarmScheduler::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return queue_.size();
}

size_t SwarmScheduler::GetCompletedCount() const {
    return completedCount_.load();
}

size_t SwarmScheduler::GetFailedCount() const {
    return failedCount_.load();
}

void SwarmScheduler::WorkerLoop(uint32_t workerId) {
    SwarmAgent agent(ctx_, workerId);
    
    while (true) {
        SwarmTask task;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [&] { return !running_ || !queue_.empty(); });
            
            if (!running_ && queue_.empty()) break;
            
            task = queue_.top();
            queue_.pop();
        }
        
        // Execute task
        SwarmTaskResult result = agent.Execute(task);
        
        // Store result
        {
            std::lock_guard<std::mutex> lock(resultsMutex_);
            results_[task.id] = result;
        }
        
        // Update stats
        if (result.success) {
            completedCount_++;
        } else {
            failedCount_++;
        }
    }
}

void SwarmScheduler::BuildGlobalTaskList(std::vector<SwarmTask>& tasks) {
    // IDE / GUI / SEG / OS - Scan tasks
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "IDE", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "GUI", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "SEG", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "OS", 0, 10, 0, ""});
    
    // IDE / GUI / SEG / OS - Repair tasks
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "IDE", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "GUI", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "SEG", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "OS", 0, 9, 0, ""});
    
    // IDE / GUI / SEG / OS - Extend tasks
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "IDE", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "GUI", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "SEG", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "OS", 0, 8, 0, ""});
    
    // IDE / GUI / SEG / OS - Optimize tasks
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "IDE", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "GUI", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "SEG", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "OS", 0, 7, 0, ""});
    
    // Unity Cycle harmonics 243-256
    for (uint32_t cycle = 243; cycle <= 256; ++cycle) {
        uint32_t priority = (cycle <= 250) ? 3 : 2; // Earlier cycles higher priority
        tasks.push_back({SwarmTaskKind::HarmonizeCycle, "Unity", cycle, priority, 0, ""});
    }
    
    // Finalization task (highest priority)
    tasks.push_back({SwarmTaskKind::FinalizeRuntime, "SovereignRuntime", 0, 0, 0, ""});
}

// SovereignSwarm implementation
SovereignSwarm::SovereignSwarm(const SwarmAgentContext& ctx) : ctx_(ctx) {}

void SovereignSwarm::SetRoleModel(ModelRole role, const RoleModelConfig& config) {
    ctx_.SetRoleModel(role, config);
}

void SovereignSwarm::SetRoleModelByName(ModelRole role, const std::string& modelName) {
    RoleModelConfig config;
    config.modelName = modelName;
    config.temperature = 0.7f;
    config.contextLength = 32768;
    ctx_.SetRoleModel(role, config);
}

void SovereignSwarm::ResetRoleModelsToDefaults() {
    ctx_.InitializeDefaultRoleModels();
}

void SovereignSwarm::PrintRoleConfiguration() const {
    std::cout << "=== SovereignSwarm Role Model Configuration ===" << std::endl;
    
    auto printRole = [this](ModelRole role, const char* name) {
        auto config = ctx_.GetRoleModel(role);
        std::cout << name << ": " << config.modelName << std::endl;
        std::cout << "  Path: " << config.modelPath << std::endl;
        std::cout << "  Quant: " << config.quantType << std::endl;
        std::cout << "  Context: " << config.contextLength << std::endl;
        std::cout << "  Temp: " << config.temperature << std::endl;
        std::cout << "  TopP: " << config.topP << std::endl;
        std::cout << "  TopK: " << config.topK << std::endl;
    };
    
    printRole(ModelRole::Scanner, "Scanner");
    printRole(ModelRole::Repairer, "Repairer");
    printRole(ModelRole::Extender, "Extender");
    printRole(ModelRole::Optimizer, "Optimizer");
    printRole(ModelRole::Harmonizer, "Harmonizer");
    printRole(ModelRole::Finalizer, "Finalizer");
    printRole(ModelRole::General, "General");
}

void SovereignSwarm::RunGlobalCompletion(InfinitePerfectionEngine& engine,
                                         InferenceBackend&         backend,
                                         ModelRegistry&            registry,
                                         SovereignCLI&             cli) {
    // Update context with provided components
    ctx_.engine = &engine;
    ctx_.backend = &backend;
    ctx_.registry = &registry;
    ctx_.cli = &cli;
    
    InitializeScheduler();
    
    std::cout << "=== Starting SovereignSwarm Global Completion ===" << std::endl;
    PrintRoleConfiguration();
    
    BuildAndEnqueueGlobalTasks();
    
    // Wait for completion
    scheduler_->WaitForCompletion();
    
    // Print results
    auto results = scheduler_->GetResults();
    size_t successCount = 0;
    size_t failCount = 0;
    
    for (const auto& result : results) {
        if (result.success) successCount++;
        else failCount++;
    }
    
    std::cout << "=== Global Completion Finished ===" << std::endl;
    std::cout << "Total tasks: " << results.size() << std::endl;
    std::cout << "Successful: " << successCount << std::endl;
    std::cout << "Failed: " << failCount << std::endl;
}

void SovereignSwarm::RunSubsystemCompletion(const std::string& target) {
    if (!scheduler_) {
        InitializeScheduler();
    }
    
    std::cout << "=== Running Subsystem Completion for " << target << " ===" << std::endl;
    
    // Enqueue tasks for this subsystem
    scheduler_->Enqueue({SwarmTaskKind::ScanSubsystem, target, 0, 10, 0, ""});
    scheduler_->Enqueue({SwarmTaskKind::RepairSubsystem, target, 0, 9, 0, ""});
    scheduler_->Enqueue({SwarmTaskKind::ExtendSubsystem, target, 0, 8, 0, ""});
    scheduler_->Enqueue({SwarmTaskKind::OptimizeSubsystem, target, 0, 7, 0, ""});
    
    scheduler_->WaitForCompletion();
    
    std::cout << "=== Subsystem Completion Finished ===" << std::endl;
}

void SovereignSwarm::RunCycleHarmonization(uint32_t startCycle, uint32_t endCycle) {
    if (!scheduler_) {
        InitializeScheduler();
    }
    
    std::cout << "=== Running Cycle Harmonization " << startCycle << "-" << endCycle << " ===" << std::endl;
    
    for (uint32_t cycle = startCycle; cycle <= endCycle; ++cycle) {
        uint32_t priority = (cycle <= 250) ? 3 : 2;
        scheduler_->Enqueue({SwarmTaskKind::HarmonizeCycle, "Unity", cycle, priority, 0, ""});
    }
    
    scheduler_->WaitForCompletion();
    
    std::cout << "=== Cycle Harmonization Finished ===" << std::endl;
}

void SovereignSwarm::RunFinalization() {
    if (!scheduler_) {
        InitializeScheduler();
    }
    
    std::cout << "=== Running Finalization ===" << std::endl;
    
    scheduler_->Enqueue({SwarmTaskKind::FinalizeRuntime, "SovereignRuntime", 0, 0, 0, ""});
    
    scheduler_->WaitForCompletion();
    
    std::cout << "=== Finalization Finished ===" << std::endl;
}

void SovereignSwarm::RunInteractiveConfiguration() {
    std::cout << "=== SovereignSwarm Interactive Configuration ===" << std::endl;
    std::cout << "Current configuration:" << std::endl;
    PrintRoleConfiguration();
    
    std::cout << "\nEnter role to configure (Scanner/Repairer/Extender/Optimizer/Harmonizer/Finalizer/General): ";
    std::string roleStr;
    std::getline(std::cin, roleStr);
    
    ModelRole role;
    if (roleStr == "Scanner") role = ModelRole::Scanner;
    else if (roleStr == "Repairer") role = ModelRole::Repairer;
    else if (roleStr == "Extender") role = ModelRole::Extender;
    else if (roleStr == "Optimizer") role = ModelRole::Optimizer;
    else if (roleStr == "Harmonizer") role = ModelRole::Harmonizer;
    else if (roleStr == "Finalizer") role = ModelRole::Finalizer;
    else role = ModelRole::General;
    
    std::cout << "Enter model name (e.g., nemotron-super:latest): ";
    std::string modelName;
    std::getline(std::cin, modelName);
    
    SetRoleModelByName(role, modelName);
    
    std::cout << "Configuration updated!" << std::endl;
}

void SovereignSwarm::InitializeScheduler() {
    scheduler_ = std::make_unique<SwarmScheduler>(ctx_);
    scheduler_->Start();
}

void SovereignSwarm::BuildAndEnqueueGlobalTasks() {
    std::vector<SwarmTask> tasks;
    
    // IDE / GUI / SEG / OS - Scan tasks
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "IDE", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "GUI", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "SEG", 0, 10, 0, ""});
    tasks.push_back({SwarmTaskKind::ScanSubsystem, "OS", 0, 10, 0, ""});
    
    // IDE / GUI / SEG / OS - Repair tasks
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "IDE", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "GUI", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "SEG", 0, 9, 0, ""});
    tasks.push_back({SwarmTaskKind::RepairSubsystem, "OS", 0, 9, 0, ""});
    
    // IDE / GUI / SEG / OS - Extend tasks
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "IDE", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "GUI", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "SEG", 0, 8, 0, ""});
    tasks.push_back({SwarmTaskKind::ExtendSubsystem, "OS", 0, 8, 0, ""});
    
    // IDE / GUI / SEG / OS - Optimize tasks
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "IDE", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "GUI", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "SEG", 0, 7, 0, ""});
    tasks.push_back({SwarmTaskKind::OptimizeSubsystem, "OS", 0, 7, 0, ""});
    
    // Unity Cycle harmonics 243-256
    for (uint32_t cycle = 243; cycle <= 256; ++cycle) {
        uint32_t priority = (cycle <= 250) ? 3 : 2;
        tasks.push_back({SwarmTaskKind::HarmonizeCycle, "Unity", cycle, priority, 0, ""});
    }
    
    // Finalization task (highest priority)
    tasks.push_back({SwarmTaskKind::FinalizeRuntime, "SovereignRuntime", 0, 0, 0, ""});
    
    // Enqueue all tasks
    for (const auto& task : tasks) {
        scheduler_->Enqueue(task);
    }
}

// SwarmUtils implementation
namespace SwarmUtils {

std::vector<std::string> GetAvailableModels(const ModelRegistry& registry) {
    return registry.GetAvailableModels();
}

std::string RecommendModelForRole(ModelRole role, const std::vector<std::string>& availableModels) {
    // Define preferred models for each role
    std::vector<std::string> preferences;
    
    switch (role) {
        case ModelRole::Scanner:
            preferences = {"nemotron-super", "qwen3.5", "gemma3"};
            break;
        case ModelRole::Repairer:
            preferences = {"qwen3.5", "deepseek-r1", "codestral"};
            break;
        case ModelRole::Extender:
            preferences = {"codestral", "qwen3.5", "gemma3"};
            break;
        case ModelRole::Optimizer:
            preferences = {"deepseek-r1", "llama3.2", "gemma3"};
            break;
        case ModelRole::Harmonizer:
            preferences = {"gemma3", "qwen3.5", "nemotron-super"};
            break;
        case ModelRole::Finalizer:
            preferences = {"bigdaddyg", "nemotron-super", "qwen3.5"};
            break;
        default:
            preferences = {"llama3.2", "gemma3", "qwen3.5"};
    }
    
    // Find first available preference
    for (const auto& pref : preferences) {
        for (const auto& available : availableModels) {
            if (available.find(pref) != std::string::npos) {
                return available;
            }
        }
    }
    
    // Return first available as fallback
    return availableModels.empty() ? "" : availableModels[0];
}

void PrintModelCapabilities(const std::string& modelName) {
    std::cout << "Model: " << modelName << std::endl;
    
    if (modelName.find("nemotron-super") != std::string::npos) {
        std::cout << "  Role: Scanner (broad understanding)" << std::endl;
        std::cout << "  Strengths: Large context, comprehensive analysis" << std::endl;
    } else if (modelName.find("qwen") != std::string::npos) {
        std::cout << "  Role: Repairer/Extender (precision)" << std::endl;
        std::cout << "  Strengths: Code accuracy, multilingual" << std::endl;
    } else if (modelName.find("codestral") != std::string::npos) {
        std::cout << "  Role: Extender (code generation)" << std::endl;
        std::cout << "  Strengths: Code completion, fill-in-the-middle" << std::endl;
    } else if (modelName.find("deepseek") != std::string::npos) {
        std::cout << "  Role: Optimizer (reasoning)" << std::endl;
        std::cout << "  Strengths: Chain-of-thought, fast inference" << std::endl;
    } else if (modelName.find("gemma") != std::string::npos) {
        std::cout << "  Role: Harmonizer (balanced)" << std::endl;
        std::cout << "  Strengths: Balanced performance, safety" << std::endl;
    } else if (modelName.find("bigdaddyg") != std::string::npos) {
        std::cout << "  Role: Finalizer (powerful)" << std::endl;
        std::cout << "  Strengths: Large capacity, finalization tasks" << std::endl;
    } else {
        std::cout << "  Role: General purpose" << std::endl;
    }
}

bool ValidateRoleModelConfig(const RoleModelConfig& config) {
    if (config.modelName.empty()) return false;
    if (config.contextLength == 0) return false;
    if (config.temperature < 0.0f || config.temperature > 2.0f) return false;
    if (config.topP < 0.0f || config.topP > 1.0f) return false;
    return true;
}

} // namespace SwarmUtils

} // namespace Sovereign
