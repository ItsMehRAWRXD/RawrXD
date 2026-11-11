// RawrXD Graceful Shutdown Manager
// Phase R.2: Graceful shutdown with drain, cleanup, and recovery
// Zero-downtime restarts and rolling updates support

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <condition_variable>

namespace RawrXD {
namespace Production {

// Forward declarations
class HealthCheckSystem;

// Shutdown phases
enum class ShutdownPhase {
    RUNNING,           // Normal operation
    DRAINING,          // Stopping new requests, completing in-flight
    CLEANUP,           // Cleaning up resources
    SHUTDOWN,          // Final shutdown
    COMPLETE           // Shutdown complete
};

// Shutdown hook priority
enum class ShutdownPriority {
    CRITICAL = 0,      // Must run first (e.g., save state)
    HIGH = 1,          // Important cleanup (e.g., close connections)
    NORMAL = 2,        // Standard cleanup
    LOW = 3,           // Optional cleanup
    BACKGROUND = 4     // Can be skipped if timeout
};

// Shutdown hook
struct ShutdownHook {
    std::string name;
    ShutdownPriority priority;
    std::chrono::seconds timeout{30};
    std::function<bool()> callback;  // Return true on success
    bool canSkip{false};               // Can be skipped if timeout
    bool runInParallel{false};         // Run concurrently with same priority
};

// Shutdown configuration
struct ShutdownConfig {
    // Timeouts
    std::chrono::seconds drainTimeout{60};      // Time to drain connections
    std::chrono::seconds cleanupTimeout{30};    // Time for cleanup
    std::chrono::seconds totalTimeout{120};     // Total shutdown timeout
    
    // Behavior
    bool forceShutdownAfterTimeout{true};       // Force exit after timeout
    bool waitForHealthChecks{true};             // Wait for health checks to pass
    bool notifyLoadBalancer{true};              // Notify LB to stop traffic
    bool saveState{true};                       // Save state before shutdown
    
    // Recovery
    bool enableRecovery{true};                  // Enable crash recovery
    std::string statePath{"/var/lib/rawrxd/state"};
};

// Shutdown status
struct ShutdownStatus {
    ShutdownPhase phase{ShutdownPhase::RUNNING};
    std::chrono::steady_clock::time_point phaseStartedAt;
    std::chrono::steady_clock::time_point shutdownStartedAt;
    
    // Progress
    uint32_t totalHooks{0};
    uint32_t completedHooks{0};
    uint32_t failedHooks{0};
    uint32_t skippedHooks{0};
    
    // Current operation
    std::string currentOperation;
    std::string currentHook;
    
    // Connections
    uint64_t activeConnections{0};
    uint64_t connectionsDrained{0};
    
    // Time remaining
    std::chrono::seconds timeRemaining;
    
    // Error info
    bool hasErrors{false};
    std::vector<std::string> errors;
};

// State snapshot for recovery
struct StateSnapshot {
    std::string version;
    std::chrono::system_clock::time_point timestamp;
    std::map<std::string, std::string> stateData;
    std::vector<std::string> activeRequests;
    std::map<std::string, std::string> sessionData;
};

// Graceful shutdown manager
class GracefulShutdownManager {
public:
    GracefulShutdownManager(HealthCheckSystem* health);
    ~GracefulShutdownManager();
    
    // Lifecycle
    bool initialize(const ShutdownConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Shutdown control
    void requestShutdown(const std::string& reason);
    void requestRestart(const std::string& reason);
    void requestReload(const std::string& reason);
    
    // Immediate shutdown (emergency)
    void emergencyShutdown(const std::string& reason);
    void forceShutdown(int exitCode = 1);
    
    // Hook registration
    bool registerHook(const ShutdownHook& hook);
    bool unregisterHook(const std::string& name);
    
    // Connection tracking
    void trackConnection(const std::string& connectionId);
    void untrackConnection(const std::string& connectionId);
    bool isConnectionActive(const std::string& connectionId) const;
    uint64_t getActiveConnectionCount() const;
    
    // Request tracking
    void trackRequest(const std::string& requestId);
    void completeRequest(const std::string& requestId);
    uint64_t getActiveRequestCount() const;
    std::vector<std::string> getActiveRequests() const;
    
    // Drain control
    void startDraining();
    bool isDraining() const { return phase_ == ShutdownPhase::DRAINING; }
    bool isDrained() const;
    void waitForDrained(std::chrono::seconds timeout);
    
    // Status
    ShutdownStatus getStatus() const;
    ShutdownPhase getPhase() const { return phase_; }
    bool isShuttingDown() const { return phase_ != ShutdownPhase::RUNNING; }
    
    // State management
    bool saveState(const StateSnapshot& state);
    std::optional<StateSnapshot> loadState();
    bool clearSavedState();
    
    // Recovery
    bool hasRecoveryState() const;
    bool recover();
    std::vector<std::string> getPendingRequestsFromRecovery() const;
    
    // Signal handling
    void setupSignalHandlers();
    void handleSignal(int signal);
    
    // Callbacks
    using PhaseChangeCallback = std::function<void(ShutdownPhase oldPhase, ShutdownPhase newPhase)>;
    void setPhaseChangeCallback(PhaseChangeCallback callback);
    
    using ProgressCallback = std::function<void(const ShutdownStatus& status)>;
    void setProgressCallback(ProgressCallback callback);

private:
    void shutdownLoop();
    void drainConnections();
    void executeHooks();
    void executeHookGroup(ShutdownPriority priority);
    void transitionToPhase(ShutdownPhase newPhase);
    void saveStateInternal();
    void notifyLoadBalancerInternal();
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::atomic<bool> shutdownRequested_{false};
    std::thread shutdownThread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    HealthCheckSystem* health_;
    ShutdownConfig config_;
    
    std::atomic<ShutdownPhase> phase_{ShutdownPhase::RUNNING};
    std::chrono::steady_clock::time_point shutdownStartedAt_;
    std::chrono::steady_clock::time_point phaseStartedAt_;
    std::string shutdownReason_;
    
    // Hooks
    std::map<ShutdownPriority, std::vector<ShutdownHook>> hooks_;
    
    // Tracking
    std::map<std::string, std::chrono::steady_clock::time_point> connections_;
    std::map<std::string, std::chrono::steady_clock::time_point> activeRequests_;
    
    // Status tracking
    uint32_t completedHooks_{0};
    uint32_t failedHooks_{0};
    uint32_t skippedHooks_{0};
    std::vector<std::string> errors_;
    
    // Callbacks
    PhaseChangeCallback phaseChangeCallback_;
    ProgressCallback progressCallback_;
};

// Process lifecycle manager
class ProcessLifecycle {
public:
    ProcessLifecycle();
    
    // Startup phases
    enum class StartupPhase {
        INITIALIZING,
        LOADING_CONFIG,
        INITIALIZING_SERVICES,
        CONNECTING_DEPENDENCIES,
        STARTING_SERVERS,
        READY,
        FAILED
    };
    
    bool initialize();
    bool markPhaseComplete(StartupPhase phase);
    bool markPhaseFailed(StartupPhase phase, const std::string& reason);
    StartupPhase getCurrentPhase() const { return currentPhase_; }
    bool isReady() const { return currentPhase_ == StartupPhase::READY; }
    
    // PID file management
    bool writePidFile(const std::string& path);
    bool removePidFile();
    bool isAnotherInstanceRunning(const std::string& path);
    
    // Daemon mode
    bool daemonize();
    bool isDaemon() const { return isDaemon_; }
    
    // Signal handling
    void setupHandlers();
    
private:
    std::atomic<StartupPhase> currentPhase_{StartupPhase::INITIALIZING};
    std::atomic<bool> isDaemon_{false};
    std::string pidFilePath_;
};

// Hot reload support
class HotReloadManager {
public:
    HotReloadManager();
    
    // Configuration reload
    bool reloadConfiguration();
    bool reloadCertificates();
    bool reloadFeatureFlags();
    
    // Code reload (plugins/modules)
    bool reloadModule(const std::string& moduleName);
    bool unloadModule(const std::string& moduleName);
    
    // Zero-downtime restart
    bool prepareZeroDowntimeRestart();
    bool executeZeroDowntimeRestart();
    bool isZeroDowntimeRestartSupported() const;
    
    // State transfer
    bool transferStateToNewProcess();
    bool receiveStateFromOldProcess();
    
private:
    std::map<std::string, std::chrono::system_clock::time_point> moduleLoadTimes_;
};

} // namespace Production
} // namespace RawrXD
