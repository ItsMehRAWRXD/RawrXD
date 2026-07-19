// ============================================================================
// WorkerCrashInjector.hpp — Worker Thread Crash Injection
// ============================================================================
// Simulates worker thread crashes/termination to validate recovery strategies.
// ============================================================================

#pragma once

#include "FaultInjector.hpp"
#include <vector>
#include <mutex>

namespace RawrXD {
namespace Validation {

// Forward declaration
struct WorkerThreadHandle;

// ============================================================================
// Worker Crash Injector
// ============================================================================
class WorkerCrashInjector : public FaultInjector {
public:
    WorkerCrashInjector();
    ~WorkerCrashInjector() override;
    
    // FaultInjector interface
    FaultType getType() const override { return FaultType::THREAD_TERMINATION; }
    std::string getName() const override { return "WorkerCrashInjector"; }
    FaultInjectionResult inject() override;
    bool isAvailable() const override;
    
    bool initialize() override;
    void shutdown() override;
    
    // Worker thread management
    void registerWorkerThread(std::thread::id id, const std::string& name);
    void unregisterWorkerThread(std::thread::id id);
    
    // Specific injection methods
    FaultInjectionResult injectByThreadId(std::thread::id id);
    FaultInjectionResult injectByName(const std::string& name);
    FaultInjectionResult injectRandomWorker();
    
    // Crash simulation modes
    enum class CrashMode {
        TERMINATE,          // std::terminate
        SEGFAULT,           // Null pointer dereference
        ABORT,              // std::abort
        EXCEPTION,          // Unhandled exception
        INFINITE_LOOP,      // Hang simulation
        STACK_OVERFLOW      // Stack exhaustion
    };
    
    void setCrashMode(CrashMode mode) { m_crashMode = mode; }
    CrashMode getCrashMode() const { return m_crashMode; }
    
    // Statistics
    size_t getRegisteredWorkerCount() const;
    std::vector<std::string> getWorkerNames() const;

private:
    struct WorkerInfo {
        std::thread::id id;
        std::string name;
        std::atomic<bool> isAlive{true};
        std::chrono::steady_clock::time_point registrationTime;
    };
    
    std::map<std::thread::id, std::shared_ptr<WorkerInfo>> m_workers;
    mutable std::mutex m_workersMutex;
    CrashMode m_crashMode = CrashMode::EXCEPTION;
    std::atomic<bool> m_initialized{false};
    
    void simulateCrash(CrashMode mode);
    std::thread::id selectRandomWorker();
};

} // namespace Validation
} // namespace RawrXD