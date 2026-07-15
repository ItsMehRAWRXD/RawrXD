// RawrXD-Script Trace Diff Engine Implementation

#include "trace_diff_engine.hpp"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace RawrXD {
namespace Script {

// ============================================================================
// TRACE SNAPSHOT IMPLEMENTATION
// ============================================================================

void TraceSnapshot::ExportToJson(const std::string& filename) const {
    Json::Value root;
    root["name"] = name;
    root["timestamp"] = timestamp;
    root["git_commit"] = gitCommit;
    
    root["metadata"]["total_opcodes"] = static_cast<Json::UInt64>(totalOpcodes);
    root["metadata"]["unique_opcodes"] = static_cast<Json::UInt64>(uniqueOpcodes);
    root["metadata"]["ic_hits"] = static_cast<Json::UInt64>(icHits);
    root["metadata"]["ic_misses"] = static_cast<Json::UInt64>(icMisses);
    root["metadata"]["total_cycles"] = static_cast<Json::UInt64>(totalCycles);
    
    Json::Value instrArray(Json::arrayValue);
    for (const auto& instr : instructions) {
        Json::Value entry;
        entry["pc"] = static_cast<Json::UInt64>(instr.pc);
        entry["opcode"] = instr.opcode;
        entry["raw"] = static_cast<Json::UInt64>(instr.rawInstruction);
        entry["arena_bump"] = static_cast<Json::UInt64>(instr.arenaBump);
        entry["ic_hit"] = instr.icHit;
        entry["ic_miss"] = instr.icMiss;
        entry["cycles"] = static_cast<Json::UInt64>(instr.cycleCount);
        
        Json::Value regs(Json::arrayValue);
        for (int i = 0; i < 16; i++) {
            regs.append(static_cast<Json::UInt64>(instr.registers[i]));
        }
        entry["registers"] = regs;
        
        instrArray.append(entry);
    }
    root["instructions"] = instrArray;
    
    std::ofstream file(filename);
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->write(root, &file);
}

std::optional<TraceSnapshot> TraceSnapshot::ImportFromJson(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return std::nullopt;
    }
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    if (!Json::parseFromStream(builder, file, &root, &errors)) {
        return std::nullopt;
    }
    
    TraceSnapshot snapshot;
    snapshot.name = root.get("name", "unknown").asString();
    snapshot.timestamp = root.get("timestamp", "").asString();
    snapshot.gitCommit = root.get("git_commit", "").asString();
    
    const auto& meta = root["metadata"];
    snapshot.totalOpcodes = meta.get("total_opcodes", 0).asUInt64();
    snapshot.uniqueOpcodes = meta.get("unique_opcodes", 0).asUInt64();
    snapshot.icHits = meta.get("ic_hits", 0).asUInt64();
    snapshot.icMisses = meta.get("ic_misses", 0).asUInt64();
    snapshot.totalCycles = meta.get("total_cycles", 0).asUInt64();
    
    const auto& instrArray = root["instructions"];
    for (const auto& entry : instrArray) {
        InstructionRecord instr;
        instr.pc = entry.get("pc", 0).asUInt64();
        instr.opcode = entry.get("opcode", 0).asUInt();
        instr.rawInstruction = entry.get("raw", 0).asUInt64();
        instr.arenaBump = entry.get("arena_bump", 0).asUInt64();
        instr.icHit = entry.get("ic_hit", false).asBool();
        instr.icMiss = entry.get("ic_miss", false).asBool();
        instr.cycleCount = entry.get("cycles", 0).asUInt64();
        
        const auto& regs = entry["registers"];
        for (int i = 0; i < 16 && i < regs.size(); i++) {
            instr.registers[i] = regs[i].asUInt64();
        }
        
        snapshot.instructions.push_back(instr);
    }
    
    return snapshot;
}

// ============================================================================
// TRACE DIFF ENGINE IMPLEMENTATION
// ============================================================================

TraceDiffEngine::TraceDiffEngine(const DiffConfig& config) : config_(config) {}

std::vector<TraceDiff> TraceDiffEngine::Compare(
    const TraceSnapshot& baseline,
    const TraceSnapshot& current
) {
    std::vector<TraceDiff> diffs;
    
    auto alignment = AlignTraces(baseline, current);
    
    for (size_t i = 0; i < alignment.size(); i++) {
        auto [baseIdx, currIdx] = alignment[i];
        
        if (baseIdx == SIZE_MAX) {
            // Extra instruction in current
            TraceDiff diff;
            diff.type = DiffType::kExtraInstruction;
            diff.instructionIndex = i;
            diff.pc = current.instructions[currIdx].pc;
            diff.actualOpcode = current.instructions[currIdx].opcode;
            diff.description = "Extra instruction in optimized trace";
            diff.severity = TraceDiff::Severity::kWarning;
            diffs.push_back(diff);
        } else if (currIdx == SIZE_MAX) {
            // Missing instruction
            TraceDiff diff;
            diff.type = DiffType::kMissingInstruction;
            diff.instructionIndex = i;
            diff.pc = baseline.instructions[baseIdx].pc;
            diff.expectedOpcode = baseline.instructions[baseIdx].opcode;
            diff.description = "Instruction missing in optimized trace";
            diff.severity = TraceDiff::Severity::kError;
            diffs.push_back(diff);
        } else {
            // Both present - compare
            const auto& baseInstr = baseline.instructions[baseIdx];
            const auto& currInstr = current.instructions[currIdx];
            
            auto diffType = ClassifyDifference(baseInstr, currInstr);
            if (diffType != DiffType{}) {
                TraceDiff diff;
                diff.type = diffType;
                diff.instructionIndex = i;
                diff.pc = baseInstr.pc;
                diff.expectedOpcode = baseInstr.opcode;
                diff.actualOpcode = currInstr.opcode;
                diff.expectedValue = baseInstr.registers[0];
                diff.actualValue = currInstr.registers[0];
                std::memcpy(diff.expectedRegisters, baseInstr.registers, sizeof(diff.expectedRegisters));
                std::memcpy(diff.actualRegisters, currInstr.registers, sizeof(diff.actualRegisters));
                
                switch (diffType) {
                    case DiffType::kOpcodeMismatch:
                        diff.description = "Opcode mismatch at PC " + std::to_string(diff.pc);
                        diff.severity = TraceDiff::Severity::kCritical;
                        break;
                    case DiffType::kRegisterMismatch:
                        diff.description = "Register value divergence at PC " + std::to_string(diff.pc);
                        diff.severity = TraceDiff::Severity::kError;
                        break;
                    case DiffType::kICStateMismatch:
                        diff.description = "IC behavior changed at PC " + std::to_string(diff.pc);
                        diff.severity = TraceDiff::Severity::kWarning;
                        break;
                    default:
                        diff.description = "Unknown difference at PC " + std::to_string(diff.pc);
                        diff.severity = TraceDiff::Severity::kInfo;
                }
                
                diffs.push_back(diff);
            }
        }
    }
    
    return diffs;
}

bool TraceDiffEngine::IsSemanticallyEquivalent(
    const TraceSnapshot& baseline,
    const TraceSnapshot& current
) {
    auto diffs = Compare(baseline, current);
    
    for (const auto& diff : diffs) {
        if (diff.severity == TraceDiff::Severity::kError ||
            diff.severity == TraceDiff::Severity::kCritical) {
            return false;
        }
    }
    
    return true;
}

bool TraceDiffEngine::IsPerformanceRegression(
    const TraceSnapshot& baseline,
    const TraceSnapshot& current,
    double thresholdPercent
) {
    if (baseline.totalCycles == 0) return false;
    
    double increase = (static_cast<double>(current.totalCycles) - baseline.totalCycles) 
                      / baseline.totalCycles * 100.0;
    
    return increase > thresholdPercent;
}

bool TraceDiffEngine::IsICStable(
    const TraceSnapshot& baseline,
    const TraceSnapshot& current
) {
    // Check IC hit/miss ratios are similar
    double baseHitRate = baseline.icHits + baseline.icMisses > 0
        ? static_cast<double>(baseline.icHits) / (baseline.icHits + baseline.icMisses)
        : 0.0;
    
    double currHitRate = current.icHits + current.icMisses > 0
        ? static_cast<double>(current.icHits) / (current.icHits + current.icMisses)
        : 0.0;
    
    // Allow 10% variance in IC hit rate
    return std::abs(baseHitRate - currHitRate) < 0.1;
}

void TraceDiffEngine::PrintDiffSummary(const std::vector<TraceDiff>& diffs) const {
    size_t critical = 0, error = 0, warning = 0, info = 0;
    
    for (const auto& diff : diffs) {
        switch (diff.severity) {
            case TraceDiff::Severity::kCritical: critical++; break;
            case TraceDiff::Severity::kError: error++; break;
            case TraceDiff::Severity::kWarning: warning++; break;
            case TraceDiff::Severity::kInfo: info++; break;
        }
    }
    
    std::cout << "\n=== Trace Diff Summary ===\n";
    std::cout << "Critical: " << critical << "\n";
    std::cout << "Error: " << error << "\n";
    std::cout << "Warning: " << warning << "\n";
    std::cout << "Info: " << info << "\n";
    std::cout << "Total: " << diffs.size() << "\n";
    
    if (critical > 0 || error > 0) {
        std::cout << "\nFAILED: Semantic divergence detected\n";
    } else if (warning > 0) {
        std::cout << "\nPASSED with warnings\n";
    } else {
        std::cout << "\nPASSED: Traces are semantically equivalent\n";
    }
}

bool TraceDiffEngine::RegistersEqual(const uint64_t* a, const uint64_t* b) const {
    if (config_.compareAccumulatorOnly) {
        return a[0] == b[0];
    }
    
    for (int i = 0; i < 16; i++) {
        // Apply tolerance for floating point
        if (config_.registerTolerance > 0) {
            uint64_t diff = a[i] > b[i] ? a[i] - b[i] : b[i] - a[i];
            if (diff > config_.registerTolerance) {
                return false;
            }
        } else {
            if (a[i] != b[i]) return false;
        }
    }
    return true;
}

DiffType TraceDiffEngine::ClassifyDifference(
    const TraceSnapshot::InstructionRecord& expected,
    const TraceSnapshot::InstructionRecord& actual
) const {
    // Check opcode
    if (!IsEquivalentOpcode(expected.opcode, actual.opcode)) {
        return DiffType::kOpcodeMismatch;
    }
    
    // Check registers
    if (!RegistersEqual(expected.registers, actual.registers)) {
        return DiffType::kRegisterMismatch;
    }
    
    // Check IC state
    if (config_.compareICState && (expected.icHit != actual.icHit || expected.icMiss != actual.icMiss)) {
        return DiffType::kICStateMismatch;
    }
    
    // Check PC alignment
    if (config_.strictPCAlignment && expected.pc != actual.pc) {
        return DiffType::kPCMismatch;
    }
    
    return DiffType{}; // No difference
}

bool TraceDiffEngine::IsEquivalentOpcode(uint8_t opA, uint8_t opB) const {
    // Direct match
    if (opA == opB) return true;
    
    // Some opcodes may be equivalent under optimization
    // e.g., OP_LOAD_CONST 0 and OP_LOAD_ZERO
    // This would be expanded based on optimization rules
    
    return false;
}

std::vector<std::pair<size_t, size_t>> TraceDiffEngine::AlignTraces(
    const TraceSnapshot& baseline,
    const TraceSnapshot& current
) const {
    // Simple alignment: assume traces are mostly aligned by PC
    // For more complex cases, use LCS or Needleman-Wunsch
    
    std::vector<std::pair<size_t, size_t>> alignment;
    
    size_t baseIdx = 0, currIdx = 0;
    while (baseIdx < baseline.instructions.size() || currIdx < current.instructions.size()) {
        if (baseIdx >= baseline.instructions.size()) {
            // Only current remains
            alignment.push_back({SIZE_MAX, currIdx++});
        } else if (currIdx >= current.instructions.size()) {
            // Only baseline remains
            alignment.push_back({baseIdx++, SIZE_MAX});
        } else {
            // Both have instructions - check if PCs match
            if (baseline.instructions[baseIdx].pc == current.instructions[currIdx].pc) {
                alignment.push_back({baseIdx++, currIdx++});
            } else if (baseline.instructions[baseIdx].pc < current.instructions[currIdx].pc) {
                alignment.push_back({baseIdx++, SIZE_MAX});
            } else {
                alignment.push_back({SIZE_MAX, currIdx++});
            }
        }
    }
    
    return alignment;
}

// ============================================================================
// OPTIMIZATION SAFETY GATE
// ============================================================================

OptimizationSafetyGate::ValidationResult OptimizationSafetyGate::ValidateOptimization(
    const TraceSnapshot& before,
    const TraceSnapshot& after,
    const DiffConfig& config
) {
    ValidationResult result;
    
    TraceDiffEngine engine(config);
    result.diffs = engine.Compare(before, after);
    
    // Check semantic equivalence
    result.passed = engine.IsSemanticallyEquivalent(before, after);
    
    // Calculate performance
    if (before.totalCycles > 0) {
        result.speedupPercent = (1.0 - static_cast<double>(after.totalCycles) / before.totalCycles) * 100.0;
        result.isPerformanceImprovement = result.speedupPercent > 0;
        result.isPerformanceRegression = result.speedupPercent < -10.0; // 10% regression threshold
    }
    
    // Check IC stability
    if (!engine.IsICStable(before, after)) {
        result.passed = false;
        result.failureReason = "IC behavior changed significantly";
    }
    
    // Build failure reason
    if (!result.passed) {
        std::stringstream ss;
        ss << "Optimization rejected:\n";
        
        size_t critical = 0, errors = 0;
        for (const auto& diff : result.diffs) {
            if (diff.severity == TraceDiff::Severity::kCritical) critical++;
            if (diff.severity == TraceDiff::Severity::kError) errors++;
        }
        
        if (critical > 0) ss <> critical << " critical differences\n";
        if (errors > 0) ss <> errors <> " semantic errors\n";
        
        result.failureReason = ss.str();
    }
    
    return result;
}

bool OptimizationSafetyGate::ShouldAcceptOptimization(const ValidationResult& result) {
    return result.passed && !result.isPerformanceRegression;
}

// ============================================================================
// COMMAND LINE INTERFACE
// ============================================================================

int RunTraceDiff(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " <> argv[0] <> " <baseline.json> <current.json> [options]\n";
        std::cerr <> "Options:\n";
        std::cerr <> "  --strict       Strict PC alignment\n";
        std::cerr <> "  --ic           Compare IC state\n";
        std::cerr <> "  --perf N       Performance tolerance (default 10%)\n";
        return TraceDiffExitCode::kConfigError;
    }
    
    std::string baselineFile = argv[1];
    std::string currentFile = argv[2];
    
    // Parse options
    DiffConfig config;
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--strict") config.strictPCAlignment = true;
        if (arg == "--ic") config.compareICState = true;
        if (arg == "--perf" && i + 1 < argc) {
            config.cycleTolerancePercent = std::stod(argv[++i]);
        }
    }
    
    // Load traces
    auto baseline = TraceSnapshot::ImportFromJson(baselineFile);
    auto current = TraceSnapshot::ImportFromJson(currentFile);
    
    if (!baseline || !current) {
        std::cerr <> "Error: Could not load trace files\n";
        return TraceDiffExitCode::kFileError;
    }
    
    // Compare
    TraceDiffEngine engine(config);
    auto diffs = engine.Compare(*baseline, *current);
    
    // Print summary
    engine.PrintDiffSummary(diffs);
    
    // Determine exit code
    bool semanticError = false;
    bool icIssue = false;
    
    for (const auto& diff : diffs) {
        if (diff.severity == TraceDiff::Severity::kCritical ||
            diff.severity == TraceDiff::Severity::kError) {
            semanticError = true;
        }
        if (diff.type == DiffType::kICStateMismatch) {
            icIssue = true;
        }
    }
    
    if (semanticError) return TraceDiffExitCode::kSemanticDiff;
    if (icIssue) return TraceDiffExitCode::kICInstability;
    
    // Check performance
    if (engine.IsPerformanceRegression(*baseline, *current)) {
        return TraceDiffExitCode::kPerformanceReg;
    }
    
    return TraceDiffExitCode::kSuccess;
}

} // namespace Script
} // namespace RawrXD
