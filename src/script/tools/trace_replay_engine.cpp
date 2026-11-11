// RawrXD-Script Trace Replay Engine Implementation

#include "trace_replay_engine.hpp"
#include "../runtime/trace_validator.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <json/json.h>

namespace RawrXD {
namespace Script {

// ============================================================================
// TRACE REPLAY ENGINE IMPLEMENTATION
// ============================================================================

TraceReplayEngine::TraceReplayEngine()
    : currentIndex_(0)
    , breakOnICMiss_(false)
    , verbose_(false)
    , stopOnDivergence_(true)
    , stopOnBreakpoint_(true)
{
    InitializeState();
}

TraceReplayEngine::~TraceReplayEngine() = default;

bool TraceReplayEngine::LoadTrace(const std::vector<TraceEntry>& trace) {
    trace_ = trace;
    currentIndex_ = 0;
    InitializeState();
    return true;
}

bool TraceReplayEngine::LoadTraceFromFile(const char* filename) {
    if (!filename) return false;
    
    std::ifstream file(filename);
    if (!file) {
        fprintf(stderr, "Failed to open trace file: %s\n", filename);
        return false;
    }
    
    // Parse JSON trace format
    std::string jsonStr((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    // Simple JSON parsing for trace entries
    // Format: {"entries": [{"pc": 0, "opcode": 1, "regs": [...]}, ...]}
    trace_.clear();
    
    // Look for entries array
    size_t entriesPos = jsonStr.find("\"entries\"");
    if (entriesPos == std::string::npos) {
        fprintf(stderr, "Invalid trace format: no 'entries' array found\n");
        return false;
    }
    
    // Parse entries (simplified - assumes well-formed JSON)
    size_t bracketPos = jsonStr.find('[', entriesPos);
    if (bracketPos == std::string::npos) return false;
    
    // For now, create a simple trace from the JSON structure
    // Full JSON parsing would require a library like nlohmann/json
    TraceEntry entry{};
    entry.pc = 0;
    entry.opcode = 0;
    trace_.push_back(entry);
    
    InitializeState();
    return true;
}

bool TraceReplayEngine::Replay(ReplayMode mode) {
    switch (mode) {
        case ReplayMode::kFull:
            return ReplayRange(0, trace_.size());
        case ReplayMode::kStep:
            return ReplayStep();
        case ReplayMode::kUntilFailure:
            return ReplayUntilDivergence();
        default:
            return false;
    }
}

bool TraceReplayEngine::ReplayStep() {
    if (currentIndex_ >= trace_.size()) {
        return false;  // End of trace
    }
    
    const auto& entry = trace_[currentIndex_];
    
    // Fire instruction event
    ReplayEvent event;
    event.type = ReplayEvent::Type::kInstruction;
    event.traceIndex = currentIndex_;
    event.description = "Executing instruction at PC=" + std::to_string(entry.pc);
    FireEvent(event);
    
    // Execute
    if (!ExecuteInstruction(entry)) {
        return false;
    }
    
    // Check for divergence
    if (CheckDivergence(entry)) {
        result_.divergencesDetected++;
        if (stopOnDivergence_) {
            return false;
        }
    }
    
    // Check breakpoints
    if (std::find(breakpoints_.begin(), breakpoints_.end(), currentIndex_) != breakpoints_.end()) {
        result_.breakpointsHit++;
        if (stopOnBreakpoint_) {
            return true;  // Stop but don't fail
        }
    }
    
    currentIndex_++;
    result_.instructionsExecuted++;
    
    return true;
}

bool TraceReplayEngine::ReplayRange(size_t start, size_t end) {
    currentIndex_ = start;
    
    for (size_t i = start; i < end && i < trace_.size(); i++) {
        if (!ReplayStep()) {
            return false;
        }
    }
    
    return true;
}

bool TraceReplayEngine::ReplayUntilDivergence() {
    while (currentIndex_ < trace_.size()) {
        if (!ReplayStep()) {
            // Check if we stopped due to divergence
            return result_.divergencesDetected == 0;
        }
    }
    
    return true;
}

ReplayState TraceReplayEngine::GetCurrentState() const {
    return currentState_;
}

std::optional<ReplayState> TraceReplayEngine::GetStateAt(size_t traceIndex) const {
    // Would need to replay up to that point
    // For now, return nullopt
    return std::nullopt;
}

TraceReplayEngine::StateDiff TraceReplayEngine::CompareStates(
    const ReplayState& expected,
    const ReplayState& actual
) {
    StateDiff diff;
    diff.pcDiffers = (expected.pc != actual.pc);
    diff.registersDiffer = false;
    diff.arenaDiffers = false;
    diff.icDiffers = false;
    
    // Compare registers
    for (int i = 0; i < 16; i++) {
        if (expected.registers[i] != actual.registers[i]) {
            diff.registersDiffer = true;
            diff.differences.push_back("Register v" + std::to_string(i) + 
                ": expected " + std::to_string(expected.registers[i]) +
                ", got " + std::to_string(actual.registers[i]));
        }
    }
    
    // Compare arena
    if (expected.arenaBump != actual.arenaBump) {
        diff.arenaDiffers = true;
        diff.differences.push_back("Arena bump differs");
    }
    
    return diff;
}

void TraceReplayEngine::SetBreakpoint(size_t traceIndex) {
    breakpoints_.push_back(traceIndex);
}

void TraceReplayEngine::SetBreakpointOnOpcode(uint8_t opcode) {
    opcodeBreakpoints_.push_back(opcode);
}

void TraceReplayEngine::SetBreakpointOnICMiss() {
    breakOnICMiss_ = true;
}

void TraceReplayEngine::ClearBreakpoint(size_t traceIndex) {
    breakpoints_.erase(
        std::remove(breakpoints_.begin(), breakpoints_.end(), traceIndex),
        breakpoints_.end()
    );
}

void TraceReplayEngine::ClearAllBreakpoints() {
    breakpoints_.clear();
    opcodeBreakpoints_.clear();
    breakOnICMiss_ = false;
}

void TraceReplayEngine::SetEventCallback(EventCallback callback) {
    eventCallback_ = callback;
}

void TraceReplayEngine::SaveSnapshot(const char* filename) {
    std::ofstream file(filename);
    if (!file) return;
    
    // TODO: Implement proper serialization
    file << "{\n";
    file << "  \"pc\": " << currentState_.pc << ",\n";
    file << "  \"instruction\": " << currentIndex_ << "\n";
    file << "}\n";
}

bool TraceReplayEngine::LoadSnapshot(const char* filename) {
    if (!filename) return false;
    
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        fprintf(stderr, "Failed to open snapshot file: %s\n", filename);
        return false;
    }
    
    // Read snapshot header
    SnapshotHeader header;
    if (!file.read(reinterpret_cast<char*>(&header), sizeof(header))) {
        fprintf(stderr, "Failed to read snapshot header\n");
        return false;
    }
    
    // Verify magic number
    if (header.magic != SNAPSHOT_MAGIC) {
        fprintf(stderr, "Invalid snapshot file (bad magic)\n");
        return false;
    }
    
    // Restore state
    currentState_.pc = header.pc;
    currentState_.instructionCount = header.instructionCount;
    
    // Read register state
    if (header.regCount > 0) {
        file.read(reinterpret_cast<char*>(currentState_.regs.data()),
                  header.regCount * sizeof(uint64_t));
    }
    
    // Read memory snapshot if present
    if (header.memorySize > 0) {
        currentState_.memory.resize(header.memorySize);
        file.read(reinterpret_cast<char*>(currentState_.memory.data()),
                  header.memorySize);
    }
    
    return file.good();
}

void TraceReplayEngine::SetSeed(uint64_t seed) {
    // For deterministic replay from fuzzer
    // Would set up random number generator, etc.
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

bool TraceReplayEngine::ExecuteInstruction(const TraceEntry& entry) {
    // Update state based on trace entry
    UpdateState(entry);
    
    if (verbose_) {
        printf("[Replay] PC=%04zu OP=0x%02X\n", entry.pc, entry.opcode);
    }
    
    return true;
}

bool TraceReplayEngine::CheckDivergence(const TraceEntry& entry) {
    // Check if current state matches expected state from trace
    // This is simplified - real implementation would compare full state
    return false;
}

void TraceReplayEngine::FireEvent(const ReplayEvent& event) {
    if (eventCallback_) {
        eventCallback_(event);
    }
    
    result_.events.push_back(event.description);
}

void TraceReplayEngine::InitializeState() {
    std::memset(&currentState_, 0, sizeof(currentState_));
    currentState_.pc = 0;
    currentState_.arenaBump = 0;
    
    result_ = ReplayResult{};
    result_.success = true;
}

void TraceReplayEngine::UpdateState(const TraceEntry& entry) {
    currentState_.pc = entry.pc;
    
    // Update registers from trace
    for (int i = 0; i < 16; i++) {
        currentState_.registers[i] = entry.regAfter[i];
    }
    
    currentState_.arenaBump = entry.arenaBumpAfter;
    currentState_.instructionCount++;
}

std::string TraceReplayEngine::StateToString(const ReplayState& state) const {
    char buffer[256];
    snprintf(buffer, sizeof(buffer),
        "PC=%llu, Arena=%llu, Instructions=%llu",
        (unsigned long long)state.pc,
        (unsigned long long)state.arenaBump,
        (unsigned long long)state.instructionCount);
    return std::string(buffer);
}

// ============================================================================
// DETERMINISTIC REPLAY
// ============================================================================

bool DeterministicReplay::SaveFuzzingRun(
    uint64_t seed,
    const std::vector<TraceEntry>& trace,
    const char* filename
) {
    std::ofstream file(filename);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"seed\": " << seed << ",\n";
    file << "  \"trace\": [\n";
    
    for (size_t i = 0; i < trace.size(); i++) {
        const auto& entry = trace[i];
        file << "    {\n";
        file << "      \"pc\": " << entry.pc << ",\n";
        file << "      \"opcode\": " << (int)entry.opcode << "\n";
        file << "    }";
        if (i < trace.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

bool DeterministicReplay::ReplayFuzzingRun(const char* filename) {
    if (!filename) return false;
    
    TraceReplayEngine engine;
    if (!engine.LoadTraceFromFile(filename)) {
        return false;
    }
    
    // Set deterministic mode
    engine.SetSeed(0xDEADBEEF); // Fixed seed for reproducibility
    
    // Replay the entire trace
    return engine.Replay(ReplayMode::kFull);
}

bool DeterministicReplay::MinimizeFuzzingRun(
    const char* inputFile,
    const char* outputFile
) {
    if (!inputFile || !outputFile) return false;
    
    // Load the original trace
    TraceReplayEngine engine;
    if (!engine.LoadTraceFromFile(inputFile)) {
        return false;
    }
    
    // Simple minimization: remove entries that don't affect the outcome
    // This is a basic implementation - full minimization would use delta debugging
    auto trace = engine.GetTrace();
    std::vector<TraceEntry> minimized;
    
    // Keep only essential entries (simplified algorithm)
    for (size_t i = 0; i < trace.size(); ++i) {
        // Keep first and last entries, and any error-inducing entries
        if (i == 0 || i == trace.size() - 1 || trace[i].errorCode != 0) {
            minimized.push_back(trace[i]);
        }
    }
    
    // Save minimized trace
    TraceReplayEngine outEngine;
    outEngine.SetTrace(minimized);
    return outEngine.SaveTraceToFile(outputFile);
}

// ============================================================================
// CRASH REPRODUCER
// ============================================================================

bool CrashReproducer::SaveCrash(
    const std::vector<TraceEntry>& trace,
    const ReplayState& state,
    const char* crashDir
) {
    if (!crashDir) return false;
    
    // Create crash directory
    std::filesystem::create_directories(crashDir);
    
    // Save trace
    std::string tracePath = std::string(crashDir) + "/crash.trace";
    TraceReplayEngine engine;
    engine.SetTrace(trace);
    if (!engine.SaveTraceToFile(tracePath.c_str())) {
        return false;
    }
    
    // Save crash metadata
    std::string metaPath = std::string(crashDir) + "/crash.json";
    std::ofstream meta(metaPath);
    if (meta) {
        meta << "{\n";
        meta << "  \"timestamp\": " << std::time(nullptr) << ",\n";
        meta << "  \"pc\": " << state.pc << ",\n";
        meta << "  \"instruction_count\": " << state.instructionCount << ",\n";
        meta << "  \"trace_entries\": " << trace.size() << "\n";
        meta << "}\n";
    }
    
    // Save memory snapshot if available
    if (!state.memory.empty()) {
        std::string memPath = std::string(crashDir) + "/memory.bin";
        std::ofstream mem(memPath, std::ios::binary);
        mem.write(reinterpret_cast<const char*>(state.memory.data()),
                  state.memory.size());
    }
    
    return true;
}

bool CrashReproducer::ReproduceCrash(const char* crashDir) {
    if (!crashDir) return false;
    
    std::string tracePath = std::string(crashDir) + "/crash.trace";
    std::string memPath = std::string(crashDir) + "/memory.bin";
    
    // Load and replay the crash trace
    TraceReplayEngine engine;
    if (!engine.LoadTraceFromFile(tracePath.c_str())) {
        return false;
    }
    
    // Load memory snapshot if available
    if (std::filesystem::exists(memPath)) {
        engine.LoadSnapshot(memPath.c_str());
    }
    
    // Replay until completion or divergence
    return engine.Replay(ReplayMode::kUntilFailure);
}

bool CrashReproducer::IsReproducible(const char* crashDir, int attempts) {
    if (!crashDir || attempts <= 0) return false;
    
    int successCount = 0;
    for (int i = 0; i < attempts; ++i) {
        if (ReproduceCrash(crashDir)) {
            successCount++;
        }
    }
    
    // Consider reproducible if it succeeds at least 80% of the time
    return (successCount * 100 / attempts) >= 80;
}

// ============================================================================
// REPLAY DEBUGGER
// ============================================================================

ReplayDebugger::ReplayDebugger(TraceReplayEngine& engine)
    : engine_(engine)
{
}

void ReplayDebugger::CommandStep() {
    engine_.ReplayStep();
    auto state = engine_.GetCurrentState();
    printf("Stepped to: PC=%llu\n", (unsigned long long)state.pc);
}

void ReplayDebugger::CommandContinue() {
    engine_.Replay();
    printf("Continued to completion\n");
}

void ReplayDebugger::CommandBack() {
    // TODO: Implement history
    printf("Back not yet implemented\n");
}

void ReplayDebugger::CommandGoto(size_t index) {
    // TODO: Implement
    printf("Goto not yet implemented\n");
}

void ReplayDebugger::CommandPrintRegisters() {
    auto state = engine_.GetCurrentState();
    printf("Registers:\n");
    for (int i = 0; i < 16; i++) {
        printf("  v%d: 0x%016llX\n", i, (unsigned long long)state.registers[i]);
    }
}

void ReplayDebugger::CommandPrintMemory(uint64_t addr, size_t len) {
    printf("Memory at 0x%016llX:\n", (unsigned long long)addr);
    // TODO: Implement memory printing
}

void ReplayDebugger::CommandPrintIC(uint32_t slot) {
    printf("IC slot %u:\n", slot);
    // TODO: Implement IC printing
}

void ReplayDebugger::CommandCompare() {
    printf("Comparing states...\n");
    // TODO: Implement comparison
}

void ReplayDebugger::CommandSave(const char* filename) {
    engine_.SaveSnapshot(filename);
    printf("Saved snapshot to %s\n", filename);
}

void ReplayDebugger::CommandLoad(const char* filename) {
    if (engine_.LoadSnapshot(filename)) {
        printf("Loaded snapshot from %s\n", filename);
    } else {
        printf("Failed to load snapshot\n");
    }
}

void ReplayDebugger::RunInteractive() {
    printf("RawrXD Trace Replay Debugger\n");
    printf("Commands: step, continue, back, goto, print, memory, ic, compare, save, load, quit\n\n");
    
    char buffer[256];
    while (true) {
        printf("(replay) ");
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            break;
        }
        
        // Parse command
        if (strncmp(buffer, "step", 4) == 0) {
            CommandStep();
        } else if (strncmp(buffer, "continue", 8) == 0) {
            CommandContinue();
        } else if (strncmp(buffer, "back", 4) == 0) {
            CommandBack();
        } else if (strncmp(buffer, "print", 5) == 0) {
            CommandPrintRegisters();
        } else if (strncmp(buffer, "memory", 6) == 0) {
            CommandPrintMemory(0, 64);  // Default address
        } else if (strncmp(buffer, "ic", 2) == 0) {
            CommandPrintIC(0);  // Default slot
        } else if (strncmp(buffer, "compare", 7) == 0) {
            CommandCompare();
        } else if (strncmp(buffer, "save", 4) == 0) {
            CommandSave("snapshot.json");
        } else if (strncmp(buffer, "load", 4) == 0) {
            CommandLoad("snapshot.json");
        } else if (strncmp(buffer, "quit", 4) == 0) {
            break;
        } else {
            printf("Unknown command: %s", buffer);
        }
    }
}

} // namespace Script
} // namespace RawrXD
