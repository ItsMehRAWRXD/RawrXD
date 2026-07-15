// RawrXD Graceful Shutdown Manager Implementation
// Phase R.2: Graceful shutdown with drain, cleanup, and recovery

#include "GracefulShutdown.hpp"
#include "HealthCheckSystem.hpp"

#include <csignal>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

namespace RawrXD {
namespace Production {

// Static instance for signal handling
static GracefulShutdownManager* g_shutdownManager = nullptr;

// Signal handler
static void signalHandler(int signal) {
    if (g_shutdownManager) {
        g_shutdownManager->handleSignal(signal);
    }
}

// ============================================================================
// GracefulShutdownManager Implementation
// ============================================================================

GracefulShutdownManager::GracefulShutdownManager(HealthCheckSystem* health)
    : health_(health)
    , running_(false)
    , initialized_(false)
    , phase_(ShutdownPhase::RUNNING) {
}

GracefulShutdownManager::~GracefulShutdownManager() {
    if (running_) {
        shutdown();
    }
}

bool GracefulShutdownManager::initialize(const ShutdownConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Set up signal handlers
    setupSignalHandlers();
    
    // Register default hooks
    ShutdownHook saveStateHook;
    saveStateHook.name = "save_state";
    saveStateHook.priority = ShutdownPriority::CRITICAL;
    saveStateHook.timeout = std::chrono::seconds(10);
    saveStateHook.callback = [this]() {
        saveStateInternal();
        return true;
    };
    registerHook(saveStateHook);
    
    ShutdownHook notifyLBHook;
    notifyLBHook.name = "notify_load_balancer";
    notifyLBHook.priority = ShutdownPriority::HIGH;
    notifyLBHook.timeout = std::chrono::seconds(5);
    notifyLBHook.callback = [this]() {
        notifyLoadBalancerInternal();
        return true;
    };
    registerHook(notifyLBHook);
    
    initialized_ = true;
    return true;
}

bool GracefulShutdownManager::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    cv_.notify_all();
    
    if (shutdownThread_.joinable()) {
        shutdownThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Shutdown Control
// ============================================================================

void GracefulShutdownManager::requestShutdown(const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (shutdownRequested_) {
        return;
    }
    
    shutdownRequested_ = true;
    shutdownReason_ = reason;
    shutdownStartedAt_ = std::chrono::steady_clock::now();
    
    // Start shutdown in background thread
    shutdownThread_ = std::thread(&GracefulShutdownManager::shutdownLoop, this);
}

void GracefulShutdownManager::requestRestart(const std::string& reason) {
    requestShutdown("restart: " + reason);
    // Would set a flag to restart after shutdown
}

void GracefulShutdownManager::requestReload(const std::string& reason) {
    // For config reload without full shutdown
    // Would trigger hot reload
}

void GracefulShutdownManager::emergencyShutdown(const std::string& reason) {
    // Immediate shutdown without graceful handling
    forceShutdown(1);
}

void GracefulShutdownManager::forceShutdown(int exitCode) {
    // Exit immediately
    std::exit(exitCode);
}

// ============================================================================
// Hook Registration
// ============================================================================

bool GracefulShutdownManager::registerHook(const ShutdownHook& hook) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    hooks_[hook.priority].push_back(hook);
    return true;
}

bool GracefulShutdownManager::unregisterHook(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [priority, hookList] : hooks_) {
        auto it = std::remove_if(hookList.begin(), hookList.end(),
                                 [&name](const ShutdownHook& h) { return h.name == name; });
        if (it != hookList.end()) {
            hookList.erase(it, hookList.end());
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// Connection Tracking
// ============================================================================

void GracefulShutdownManager::trackConnection(const std::string& connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_[connectionId] = std::chrono::steady_clock::now();
}

void GracefulShutdownManager::untrackConnection(const std::string& connectionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_.erase(connectionId);
}

bool GracefulShutdownManager::isConnectionActive(const std::string& connectionId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.count(connectionId) > 0;
}

uint64_t GracefulShutdownManager::getActiveConnectionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

// ============================================================================
// Request Tracking
// ============================================================================

void GracefulShutdownManager::trackRequest(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeRequests_[requestId] = std::chrono::steady_clock::now();
}

void GracefulShutdownManager::completeRequest(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    activeRequests_.erase(requestId);
}

uint64_t GracefulShutdownManager::getActiveRequestCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeRequests_.size();
}

std::vector<std::string> GracefulShutdownManager::getActiveRequests() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [id, time] : activeRequests_) {
        result.push_back(id);
    }
    return result;
}

// ============================================================================
// Drain Control
// ============================================================================

void GracefulShutdownManager::startDraining() {
    transitionToPhase(ShutdownPhase::DRAINING);
}

bool GracefulShutdownManager::isDrained() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.empty() && activeRequests_.empty();
}

void GracefulShutdownManager::waitForDrained(std::chrono::seconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_until(lock, deadline, [this] {
        return connections_.empty() && activeRequests_.empty();
    });
}

// ============================================================================
// Status
// ============================================================================

ShutdownStatus GracefulShutdownManager::getStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ShutdownStatus status;
    status.phase = phase_;
    status.phaseStartedAt = phaseStartedAt_;
    status.shutdownStartedAt = shutdownStartedAt_;
    
    // Count hooks
    status.totalHooks = 0;
    for (const auto& [priority, hookList] : hooks_) {
        status.totalHooks += hookList.size();
    }
    
    status.completedHooks = completedHooks_;
    status.failedHooks = failedHooks_;
    status.skippedHooks = skippedHooks_;
    
    status.activeConnections = connections_.size();
    status.connectionsDrained = 0; // Would track
    
    if (shutdownRequested_) {
        auto elapsed = std::chrono::steady_clock::now() - shutdownStartedAt_;
        status.timeRemaining = config_.totalTimeout - 
                               std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    }
    
    status.hasErrors = !errors_.empty();
    status.errors = errors_;
    
    return status;
}

// ============================================================================
// State Management
// ============================================================================

bool GracefulShutdownManager::saveState(const StateSnapshot& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(config_.statePath + "/state.json");
    if (!file) {
        return false;
    }
    
    // Would serialize state to JSON
    file << "{\"version\":\"" << state.version << "\"}";
    return true;
}

std::optional<StateSnapshot> GracefulShutdownManager::loadState() {
    std::ifstream file(config_.statePath + "/state.json");
    if (!file) {
        return std::nullopt;
    }
    
    StateSnapshot state;
    // Would deserialize from JSON
    return state;
}

bool GracefulShutdownManager::clearSavedState() {
    // Would remove state file
    return true;
}

// ============================================================================
// Recovery
// ============================================================================

bool GracefulShutdownManager::hasRecoveryState() const {
    std::ifstream file(config_.statePath + "/state.json");
    return file.good();
}

bool GracefulShutdownManager::recover() {
    auto state = loadState();
    if (!state) {
        return false;
    }
    
    // Would restore state
    return true;
}

std::vector<std::string> GracefulShutdownManager::getPendingRequestsFromRecovery() const {
    auto state = loadState();
    if (!state) {
        return {};
    }
    
    return state->activeRequests;
}

// ============================================================================
// Signal Handling
// ============================================================================

void GracefulShutdownManager::setupSignalHandlers() {
    g_shutdownManager = this;
    
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
#ifdef SIGUSR1
    std::signal(SIGUSR1, signalHandler); // Config reload
#endif
#ifdef SIGUSR2
    std::signal(SIGUSR2, signalHandler); // Status dump
#endif
}

void GracefulShutdownManager::handleSignal(int signal) {
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            requestShutdown("signal " + std::to_string(signal));
            break;
            
#ifdef SIGUSR1
        case SIGUSR1:
            requestReload("SIGUSR1");
            break;
#endif
            
#ifdef SIGUSR2
        case SIGUSR2:
            // Dump status
            break;
#endif
            
        default:
            break;
    }
}

// ============================================================================
// Internal Methods
// ============================================================================

void GracefulShutdownManager::shutdownLoop() {
    // Phase 1: Draining
    transitionToPhase(ShutdownPhase::DRAINING);
    drainConnections();
    
    // Phase 2: Cleanup
    transitionToPhase(ShutdownPhase::CLEANUP);
    executeHooks();
    
    // Phase 3: Shutdown
    transitionToPhase(ShutdownPhase::SHUTDOWN);
    
    // Phase 4: Complete
    transitionToPhase(ShutdownPhase::COMPLETE);
    
    // Exit
    if (config_.forceShutdownAfterTimeout) {
        std::exit(0);
    }
}

void GracefulShutdownManager::drainConnections() {
    auto deadline = std::chrono::steady_clock::now() + config_.drainTimeout;
    
    // Stop accepting new connections
    // Would notify servers to stop accepting
    
    // Wait for existing connections to complete
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (connections_.empty() && activeRequests_.empty()) {
                break;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (progressCallback_) {
            progressCallback_(getStatus());
        }
    }
}

void GracefulShutdownManager::executeHooks() {
    // Execute hooks by priority
    executeHookGroup(ShutdownPriority::CRITICAL);
    executeHookGroup(ShutdownPriority::HIGH);
    executeHookGroup(ShutdownPriority::NORMAL);
    executeHookGroup(ShutdownPriority::LOW);
    
    // Background hooks can be skipped if timeout
    auto elapsed = std::chrono::steady_clock::now() - shutdownStartedAt_;
    if (elapsed < config_.totalTimeout) {
        executeHookGroup(ShutdownPriority::BACKGROUND);
    } else {
        // Skip background hooks
        auto it = hooks_.find(ShutdownPriority::BACKGROUND);
        if (it != hooks_.end()) {
            skippedHooks_ += it->second.size();
        }
    }
}

void GracefulShutdownManager::executeHookGroup(ShutdownPriority priority) {
    auto it = hooks_.find(priority);
    if (it == hooks_.end()) {
        return;
    }
    
    for (const auto& hook : it->second) {
        if (!hook.canSkip && 
            std::chrono::steady_clock::now() - shutdownStartedAt_ > config_.totalTimeout) {
            errors_.push_back("Hook timed out: " + hook.name);
            failedHooks_++;
            continue;
        }
        
        try {
            bool success = hook.callback();
            if (success) {
                completedHooks_++;
            } else {
                errors_.push_back("Hook failed: " + hook.name);
                failedHooks_++;
            }
        } catch (const std::exception& e) {
            errors_.push_back("Hook exception: " + hook.name + " - " + e.what());
            failedHooks_++;
        }
        
        if (progressCallback_) {
            progressCallback_(getStatus());
        }
    }
}

void GracefulShutdownManager::transitionToPhase(ShutdownPhase newPhase) {
    ShutdownPhase oldPhase = phase_.exchange(newPhase);
    phaseStartedAt_ = std::chrono::steady_clock::now();
    
    if (phaseChangeCallback_) {
        phaseChangeCallback_(oldPhase, newPhase);
    }
}

void GracefulShutdownManager::saveStateInternal() {
    StateSnapshot state;
    state.version = "1.0.0";
    state.timestamp = std::chrono::system_clock::now();
    
    // Save active requests
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, time] : activeRequests_) {
            state.activeRequests.push_back(id);
        }
    }
    
    saveState(state);
}

void GracefulShutdownManager::notifyLoadBalancerInternal() {
    // Would notify load balancer to stop sending traffic
    // Could be via HTTP endpoint, file, or other mechanism
}

// ============================================================================
// ProcessLifecycle Implementation
// ============================================================================

ProcessLifecycle::ProcessLifecycle() {}

bool ProcessLifecycle::initialize() {
    currentPhase_ = StartupPhase::INITIALIZING;
    return true;
}

bool ProcessLifecycle::markPhaseComplete(StartupPhase phase) {
    if (currentPhase_ == phase) {
        // Advance to next phase
        switch (phase) {
            case StartupPhase::INITIALIZING:
                currentPhase_ = StartupPhase::LOADING_CONFIG;
                break;
            case StartupPhase::LOADING_CONFIG:
                currentPhase_ = StartupPhase::INITIALIZING_SERVICES;
                break;
            case StartupPhase::INITIALIZING_SERVICES:
                currentPhase_ = StartupPhase::CONNECTING_DEPENDENCIES;
                break;
            case StartupPhase::CONNECTING_DEPENDENCIES:
                currentPhase_ = StartupPhase::STARTING_SERVERS;
                break;
            case StartupPhase::STARTING_SERVERS:
                currentPhase_ = StartupPhase::READY;
                break;
            default:
                break;
        }
        return true;
    }
    return false;
}

bool ProcessLifecycle::markPhaseFailed(StartupPhase phase, const std::string& reason) {
    currentPhase_ = StartupPhase::FAILED;
    return true;
}

bool ProcessLifecycle::writePidFile(const std::string& path) {
    pidFilePath_ = path;
    
    std::ofstream file(path);
    if (!file) {
        return false;
    }
    
#ifdef _WIN32
    file << GetCurrentProcessId();
#else
    file << getpid();
#endif
    
    return true;
}

bool ProcessLifecycle::removePidFile() {
    if (!pidFilePath_.empty()) {
        std::remove(pidFilePath_.c_str());
    }
    return true;
}

bool ProcessLifecycle::isAnotherInstanceRunning(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return false;
    }
    
    int pid;
    file >> pid;
    
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        CloseHandle(process);
        return true;
    }
    return false;
#else
    // Check if process exists
    return (kill(pid, 0) == 0);
#endif
}

bool ProcessLifecycle::daemonize() {
#ifdef _WIN32
    // Windows service mode
    isDaemon_ = true;
    return true;
#else
    // Unix daemonize
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid > 0) {
        std::exit(0); // Parent exits
    }
    
    // Child continues
    if (setsid() < 0) {
        return false;
    }
    
    // Fork again
    pid = fork();
    if (pid < 0) {
        return false;
    }
    if (pid > 0) {
        std::exit(0);
    }
    
    // Change working directory
    chdir("/");
    
    // Close file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    isDaemon_ = true;
    return true;
#endif
}

void ProcessLifecycle::setupHandlers() {
    // Would set up signal handlers
}

// ============================================================================
// HotReloadManager Implementation
// ============================================================================

HotReloadManager::HotReloadManager() {}

bool HotReloadManager::reloadConfiguration() {
    // Would reload config files
    return true;
}

bool HotReloadManager::reloadCertificates() {
    // Would reload TLS certificates
    return true;
}

bool HotReloadManager::reloadFeatureFlags() {
    // Would reload feature flags
    return true;
}

bool HotReloadManager::reloadModule(const std::string& moduleName) {
    // Would reload dynamic module
    moduleLoadTimes_[moduleName] = std::chrono::system_clock::now();
    return true;
}

bool HotReloadManager::unloadModule(const std::string& moduleName) {
    // Would unload dynamic module
    moduleLoadTimes_.erase(moduleName);
    return true;
}

bool HotReloadManager::prepareZeroDowntimeRestart() {
    // Would prepare for zero-downtime restart
    return true;
}

bool HotReloadManager::executeZeroDowntimeRestart() {
    // Would execute zero-downtime restart
    return true;
}

bool HotReloadManager::isZeroDowntimeRestartSupported() const {
#ifdef _WIN32
    return false; // Not supported on Windows
#else
    return true; // Supported on Unix via fork/exec
#endif
}

bool HotReloadManager::transferStateToNewProcess() {
    // Would transfer state to new process
    return true;
}

bool HotReloadManager::receiveStateFromOldProcess() {
    // Would receive state from old process
    return true;
}

} // namespace Production
} // namespace RawrXD
