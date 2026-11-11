// Build System Telemetry - Structured Events from Compiler/Linker
//
// Converts compiler/linker output into machine-readable events instead of terminal text.
// This eliminates polling loops and enables event-driven build orchestration.
//
// Architecture:
//   Compiler/Linker
//        |
//        v
//   Build Telemetry Hook
//        |
//        v
//   Beacon Bus (structured events)
//        |
//        v
//   Agent Kernel (event-driven)

#pragma once

#include "AgentKernel.hpp"

#include <cstdint.h>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Kernel {

// Forward declarations
class BuildProcess;
class BuildTelemetryCollector;

// ============================================================================
// Build Event Types - Structured compiler/linker output
// ============================================================================

enum class BuildEventType : uint32_t {
    // Process lifecycle
    PROCESS_STARTED = 0,
    PROCESS_COMPLETED = 1,
    PROCESS_FAILED = 2,
    PROCESS_CANCELLED = 3,
    
    // Compilation events
    COMPILATION_STARTED = 10,
    COMPILATION_PROGRESS = 11,
    COMPILATION_COMPLETED = 12,
    COMPILATION_WARNING = 13,
    COMPILATION_ERROR = 14,
    
    // Link events
    LINK_STARTED = 20,
    LINK_PROGRESS = 21,
    LINK_COMPLETED = 22,
    LINK_ERROR = 23,
    
    // Analysis events
    STATIC_ANALYSIS_STARTED = 30,
    STATIC_ANALYSIS_WARNING = 31,
    STATIC_ANALYSIS_ERROR = 32,
    STATIC_ANALYSIS_COMPLETED = 33,
    
    // Dependency events
    DEPENDENCY_SCAN_STARTED = 40,
    DEPENDENCY_DISCOVERED = 41,
    DEPENDENCY_RESOLVED = 42,
    DEPENDENCY_MISSING = 43,
    
    // Build graph events
    TARGET_STARTED = 50,
    TARGET_COMPLETED = 51,
    TARGET_FAILED = 52,
    TARGET_SKIPPED = 53,
    
    // Resource events
    MEMORY_PRESSURE = 60,
    DISK_IO_HIGH = 61,
    CPU_THROTTLE = 62,
    
    // Custom
    CUSTOM = 100
};

const char* BuildEventTypeToString(BuildEventType type);

// ============================================================================
// Structured Build Event - Machine-readable compiler output
// ============================================================================

struct BuildEvent {
    uint64_t eventId;
    BuildEventType type;
    uint64_t timestamp;
    uint64_t processId;
    
    // Source location
    std::string filePath;
    uint32_t lineNumber;
    uint32_t columnNumber;
    
    // Event details
    std::string message;
    std::string errorCode;      // e.g., "C1234" for MSVC
    std::string severity;       // "info", "warning", "error", "fatal"
    
    // Structured data
    std::unordered_map<std::string, std::string> metadata;
    
    // Compilation-specific
    std::string compilerCommand;
    std::vector<std::string> compilerArgs;
    std::string sourceFile;
    std::string objectFile;
    
    // Timing
    uint64_t durationMs;
    uint64_t memoryUsedBytes;
    
    // Serialization
    std::string ToJson() const;
    std::string ToCompilerFormat() const;  // Convert back to compiler-style output
    
    // Factory methods for common events
    static BuildEvent MakeCompilationStarted(const std::string& sourceFile,
                                              const std::string& command);
    static BuildEvent MakeCompilationError(const std::string& sourceFile,
                                            uint32_t line, uint32_t col,
                                            const std::string& message,
                                            const std::string& errorCode);
    static BuildEvent MakeCompilationWarning(const std::string& sourceFile,
                                              uint32_t line, uint32_t col,
                                              const std::string& message,
                                              const std::string& warningCode);
    static BuildEvent MakeLinkStarted(const std::vector<std::string>& objectFiles);
    static BuildEvent MakeLinkCompleted(const std::string& executable,
                                         uint64_t durationMs);
};

// ============================================================================
// Build Process - Track a single compiler/linker invocation
// ============================================================================

enum class BuildProcessState {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
};

class BuildProcess {
public:
    uint64_t processId;
    std::string processType;    // "compile", "link", "analyze"
    std::string command;
    std::vector<std::string> args;
    
    // State
    BuildProcessState state;
    uint64_t startTime;
    uint64_t endTime;
    
    // Progress
    uint64_t totalWork;
    uint64_t completedWork;
    std::string currentAction;
    
    // Results
    std::vector<BuildEvent> events;
    uint32_t errorCount;
    uint32_t warningCount;
    
    // Resources
    uint64_t peakMemoryBytes;
    uint64_t cpuTimeMs;
    
    // Methods
    BuildProcess(uint64_t id, const std::string& type);
    
    void Start();
    void UpdateProgress(uint64_t completed, uint64_t total, const std::string& action);
    void AddEvent(const BuildEvent& event);
    void Complete(bool success);
    void Cancel();
    
    double GetProgressPercent() const;
    uint64_t GetDurationMs() const;
    bool HasErrors() const { return errorCount > 0; }
    bool HasWarnings() const { return warningCount > 0; }
    
    std::string GetSummary() const;
};

// ============================================================================
// Build Graph - Dependency-aware build tracking
// ============================================================================

struct BuildTarget {
    std::string name;
    std::string type;           // "executable", "library", "object"
    std::vector<std::string> sourceFiles;
    std::vector<std::string> dependencies;  // Other target names
    std::vector<std::string> objectFiles;
    std::string outputPath;
    
    // State
    bool isUpToDate;
    bool isBuilding;
    bool isComplete;
    bool hasErrors;
    
    // Timing
    uint64_t startTime;
    uint64_t endTime;
};

class BuildGraph {
public:
    void AddTarget(const BuildTarget& target);
    void AddDependency(const std::string& from, const std::string& to);
    
    // Query
    std::vector<std::string> GetBuildOrder() const;  // Topologically sorted
    std::vector<std::string> GetReadyTargets() const;  // Dependencies satisfied
    std::vector<std::string> GetDependents(const std::string& target) const;
    
    // State updates
    void MarkTargetStarted(const std::string& target);
    void MarkTargetCompleted(const std::string& target, bool success);
    void MarkTargetUpToDate(const std::string& target);
    
    // Status
    bool IsComplete() const;
    bool HasErrors() const;
    size_t GetCompletedCount() const;
    size_t GetTotalCount() const;
    double GetProgressPercent() const;
    
    // Serialization
    std::string ToJson() const;
    static BuildGraph FromCmake(const std::string& buildDir);
    
private:
    std::unordered_map<std::string, BuildTarget> targets_;
    std::unordered_map<std::string, std::vector<std::string>> dependencyGraph_;
    
    bool AreDependenciesSatisfied(const std::string& target) const;
};

// ============================================================================
// Build Telemetry Collector - Hook into compiler/linker
// ============================================================================

class BuildTelemetryCollector {
public:
    static BuildTelemetryCollector& Instance();
    
    // Lifecycle
    void Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Process management
    uint64_t StartProcess(const std::string& type, const std::string& command,
                          const std::vector<std::string>& args);
    void EndProcess(uint64_t processId, bool success);
    void CancelProcess(uint64_t processId);
    
    // Event injection (called by hooks)
    void InjectEvent(uint64_t processId, const BuildEvent& event);
    void InjectCompilationStarted(uint64_t processId, const std::string& sourceFile);
    void InjectCompilationError(uint64_t processId, const std::string& sourceFile,
                                 uint32_t line, const std::string& message);
    void InjectCompilationWarning(uint64_t processId, const std::string& sourceFile,
                                     uint32_t line, const std::string& message);
    void InjectLinkStarted(uint64_t processId);
    void InjectLinkCompleted(uint64_t processId, const std::string& executable);
    void InjectLinkError(uint64_t processId, const std::string& message);
    
    // Progress updates
    void UpdateProgress(uint64_t processId, uint64_t completed, uint64_t total);
    
    // Query
    std::shared_ptr<BuildProcess> GetProcess(uint64_t processId) const;
    std::vector<std::shared_ptr<BuildProcess>> GetActiveProcesses() const;
    std::vector<std::shared_ptr<BuildProcess>> GetRecentProcesses(size_t max = 100) const;
    
    // Statistics
    struct CollectorStats {
        uint64_t totalProcesses;
        uint64_t activeProcesses;
        uint64_t completedProcesses;
        uint64_t failedProcesses;
        uint64_t totalEvents;
        uint64_t totalErrors;
        uint64_t totalWarnings;
    };
    CollectorStats GetStats() const;
    
    // Integration with Agent Kernel
    void ConnectToBeaconBus();
    void DisconnectFromBeaconBus();
    
private:
    BuildTelemetryCollector() = default;
    
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> nextProcessId_{1};
    
    mutable std::mutex processesMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<BuildProcess>> processes_;
    std::vector<uint64_t> recentProcesses_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    CollectorStats stats_{};
    
    // Beacon integration
    uint64_t beaconSubscriptionId_{0};
    
    void PublishToBeacon(const BuildEvent& event);
    void OnBeaconEvent(const BeaconEvent& event);
};

// ============================================================================
// Compiler Hooks - Intercept compiler output
// ============================================================================

class CompilerHooks {
public:
    // Install hooks into various build systems
    static void InstallMSVCHooks();      // cl.exe, link.exe
    static void InstallClangHooks();     // clang, clang++
    static void InstallGCCHooks();       // gcc, g++
    static void InstallCMakeHooks();     // cmake --build
    static void InstallNinjaHooks();     // ninja
    static void InstallMSBuildHooks();   // MSBuild
    
    // Parse compiler output
    static std::vector<BuildEvent> ParseMSVCOutput(const std::string& output);
    static std::vector<BuildEvent> ParseClangOutput(const std::string& output);
    static std::vector<BuildEvent> ParseGCCOutput(const std::string& output);
    
    // Event patterns
    static bool IsCompilationStart(const std::string& line);
    static bool IsCompilationError(const std::string& line);
    static bool IsCompilationWarning(const std::string& line);
    static bool IsLinkStart(const std::string& line);
    static bool IsLinkComplete(const std::string& line);
};

// ============================================================================
// Build Telemetry API - Convenience functions
// ============================================================================

#define BUILD_TELEMETRY RawrXD::Kernel::BuildTelemetryCollector::Instance()

// Quick start build
inline uint64_t StartBuild(const std::string& command) {
    return BUILD_TELEMETRY.StartProcess("build", command, {});
}

// Quick compilation
inline uint64_t StartCompilation(const std::string& sourceFile,
                                  const std::string& compiler) {
    return BUILD_TELEMETRY.StartProcess("compile", 
                                          compiler + " " + sourceFile,
                                          {sourceFile});
}

// Scoped build tracking
class ScopedBuildProcess {
public:
    ScopedBuildProcess(const std::string& type, const std::string& command);
    ~ScopedBuildProcess();
    
    void MarkSuccess();
    void MarkFailed(const std::string& error);
    void AddEvent(const BuildEvent& event);
    
private:
    uint64_t processId_;
    bool finalized_{false};
};

} // namespace Kernel
} // namespace RawrXD
