// RawrXD-Script Bidirectional Trace Replay Engine
// Replays execution traces deterministically for debugging
// Enables: debugging without recompilation, VM state snapshots, crash reproduction

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Script {

// Forward declarations
struct TraceEntry;
struct JsValue;

// ============================================================================
// REPLAY STATE SNAPSHOT
// ============================================================================

struct ReplayState {
    uint64_t pc;                    // Program counter
    uint64_t registers[16];         // Virtual register file (v0-v15)
    uint64_t arenaBump;             // Arena allocation pointer
    uint64_t icTableBase;           // IC table base address
    uint64_t globalObject;          // Global object pointer
    
    // Memory state (for arena)
    std::vector<uint8_t> arenaSnapshot;
    size_t arenaSnapshotOffset;
    
    // IC state
    std::map<uint32_t, uint8_t> icStates;  // slot -> state
    
    // Metadata
    uint64_t instructionCount;
    uint64_t cycleCount;
};

// ============================================================================
// REPLAY EVENT
// ============================================================================

struct ReplayEvent {
    enum class Type {
        kInstruction,       // Execute one instruction
        kBreakpoint,        // Pause execution
        kMemoryRead,        // Read from arena
        kMemoryWrite,       // Write to arena
        kICAccess,          // IC hit/miss
        kException,         // Exception thrown
        kSnapshot,          // State snapshot
        kCompare            // Compare state to expected
    };
    
    Type type;
    size_t traceIndex;      // Index in original trace
    std::string description;
};

// ============================================================================
// TRACE REPLAY ENGINE
// ============================================================================

class TraceReplayEngine {
public:
    TraceReplayEngine();
    ~TraceReplayEngine();
    
    // Load a trace for replay
    bool LoadTrace(const std::vector<TraceEntry>& trace);
    bool LoadTraceFromFile(const char* filename);
    
    // Replay modes
    enum class ReplayMode {
        kFull,              // Replay entire trace
        kStep,              // Step through one instruction at a time
        kRange,             // Replay specific range
        kUntilFailure       // Replay until divergence detected
    };
    
    // Execute replay
    bool Replay(ReplayMode mode = ReplayMode::kFull);
    bool ReplayStep();                    // Execute one instruction
    bool ReplayRange(size_t start, size_t end);
    bool ReplayUntilDivergence();
    
    // State inspection
    ReplayState GetCurrentState() const;
    std::optional<ReplayState> GetStateAt(size_t traceIndex) const;
    
    // State comparison
    struct StateDiff {
        bool pcDiffers;
        bool registersDiffer;
        bool arenaDiffers;
        bool icDiffers;
        std::vector<std::string> differences;
    };
    
    StateDiff CompareStates(const ReplayState& expected, const ReplayState& actual);
    
    // Breakpoints
    void SetBreakpoint(size_t traceIndex);
    void SetBreakpointOnOpcode(uint8_t opcode);
    void SetBreakpointOnICMiss();
    void ClearBreakpoint(size_t traceIndex);
    void ClearAllBreakpoints();
    
    // Event callbacks
    using EventCallback = std::function<void(const ReplayEvent&)>;
    void SetEventCallback(EventCallback callback);
    
    // Snapshot management
    void SaveSnapshot(const char* filename);
    bool LoadSnapshot(const char* filename);
    
    // Deterministic replay from seed
    void SetSeed(uint64_t seed);
    
    // Results
    struct ReplayResult {
        bool success;
        size_t instructionsExecuted;
        size_t breakpointsHit;
        size_t divergencesDetected;
        std::vector<std::string> events;
        std::optional<ReplayState> finalState;
    };
    
    ReplayResult GetResult() const { return result_; }
    
    // Configuration
    void SetVerbose(bool verbose) { verbose_ = verbose; }
    void SetStopOnDivergence(bool stop) { stopOnDivergence_ = stop; }
    void SetStopOnBreakpoint(bool stop) { stopOnBreakpoint_ = stop; }
    
private:
    std::vector<TraceEntry> trace_;
    size_t currentIndex_;
    ReplayState currentState_;
    ReplayResult result_;
    
    std::vector<size_t> breakpoints_;
    std::vector<uint8_t> opcodeBreakpoints_;
    bool breakOnICMiss_;
    
    EventCallback eventCallback_;
    bool verbose_;
    bool stopOnDivergence_;
    bool stopOnBreakpoint_;
    
    // Execution
    bool ExecuteInstruction(const TraceEntry& entry);
    bool CheckDivergence(const TraceEntry& entry);
    void FireEvent(const ReplayEvent& event);
    
    // State management
    void InitializeState();
    void UpdateState(const TraceEntry& entry);
    
    // Helper
    std::string StateToString(const ReplayState& state) const;
};

// ============================================================================
// DETERMINISTIC REPLAY FROM FUZZER
// ============================================================================

class DeterministicReplay {
public:
    // Save a fuzzing run for later replay
    static bool SaveFuzzingRun(
        uint64_t seed,
        const std::vector<TraceEntry>& trace,
        const char* filename
    );
    
    // Replay a saved fuzzing run
    static bool ReplayFuzzingRun(const char* filename);
    
    // Minimize a failing fuzzing run
    static bool MinimizeFuzzingRun(
        const char* inputFile,
        const char* outputFile
    );
};

// ============================================================================
// CRASH REPRODUCER
// ============================================================================

class CrashReproducer {
public:
    // Save crash state
    static bool SaveCrash(
        const std::vector<TraceEntry>& trace,
        const ReplayState& state,
        const char* crashDir
    );
    
    // Reproduce a crash
    static bool ReproduceCrash(const char* crashDir);
    
    // Check if crash is reproducible
    static bool IsReproducible(const char* crashDir, int attempts = 3);
};

// ============================================================================
// DEBUGGING COMMANDS
// ============================================================================

class ReplayDebugger {
public:
    ReplayDebugger(TraceReplayEngine& engine);
    
    // Interactive commands
    void CommandStep();                     // Execute one instruction
    void CommandContinue();                 // Continue to next breakpoint
    void CommandBack();                     // Step back one instruction
    void CommandGoto(size_t index);         // Jump to specific instruction
    void CommandPrintRegisters();           // Show register state
    void CommandPrintMemory(uint64_t addr, size_t len);
    void CommandPrintIC(uint32_t slot);
    void CommandCompare();                  // Compare to expected trace
    void CommandSave(const char* filename);
    void CommandLoad(const char* filename);
    
    // Run interactive session
    void RunInteractive();
    
private:
    TraceReplayEngine& engine_;
    std::vector<ReplayState> history_;  // For back command
};

} // namespace Script
} // namespace RawrXD
