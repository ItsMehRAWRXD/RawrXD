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
    // TODO: Implement JSON trace loading
    return false;
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
    // TODO: Implement proper deserialization
    return false;
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
    // TODO: Implement
    return false;
}

bool DeterministicReplay::MinimizeFuzzingRun(
    const char* inputFile,
    const char* outputFile
) {
    // TODO: Implement using TraceMinimizer
    return false;
}

// ============================================================================
// CRASH REPRODUCER
// ============================================================================

bool CrashReproducer::SaveCrash(
    const std::vector<TraceEntry>& trace,
    const ReplayState& state,
    const char* crashDir
) {
    // TODO: Implement
    return false;
}

bool CrashReproducer::ReproduceCrash(const char* crashDir) {
    // TODO: Implement
    return false;
}

bool CrashReproducer::IsReproducible(const char* crashDir, int attempts) {
    // TODO: Implement
    return false;
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
