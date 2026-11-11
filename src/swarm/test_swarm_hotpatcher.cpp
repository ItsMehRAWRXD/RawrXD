// ============================================================================
// test_swarm_hotpatcher.cpp - Demonstration of Swarm Hotpatcher Framework
// ============================================================================

#include "SwarmHotpatcher.hpp"
#include <iostream>
#include <iomanip>

using namespace Sovereign;

void PrintSeparator() {
    std::cout << "═══════════════════════════════════════════════════════════════════\n";
}

void PrintHeader(const std::string& title) {
    PrintSeparator();
    std::cout << "  " << title << "\n";
    PrintSeparator();
    std::cout << std::endl;
}

void PrintResult(const ValidationResult& result) {
    const char* statusIcon = "?";
    switch (result.status) {
        case ValidationStatus::PASS: statusIcon = "✓ PASS"; break;
        case ValidationStatus::FAIL: statusIcon = "✗ FAIL"; break;
        case ValidationStatus::WARNING: statusIcon = "⚠ WARNING"; break;
        case ValidationStatus::SKIP: statusIcon = "⊘ SKIP"; break;
        default: statusIcon = "? UNKNOWN"; break;
    }
    
    std::cout << "  " << std::left << std::setw(12) << result.gateId << " | "
              << std::setw(10) << statusIcon << " | "
              << std::setw(6) << std::fixed << std::setprecision(1) << result.score << "% | "
              << result.durationMs << "ms\n";
    
    if (!result.regressions.empty()) {
        for (const auto& reg : result.regressions) {
            std::cout << "    ⚠ Regression: " << reg.description << "\n";
            std::cout << "      Deviation: " << std::showpos << reg.deviationPercent << std::noshowpos << "%\n";
            std::cout << "      Recommendation: " << reg.recommendation << "\n";
        }
    }
}

void PrintMasterReport(const MasterGateReport& report) {
    PrintHeader("MASTER GATE REPORT");
    
    std::cout << "Report ID: " << report.reportId << "\n";
    std::cout << "Generated: " << std::chrono::system_clock::to_time_t(report.generatedAt) << "\n\n";
    
    PrintSeparator();
    std::cout << "SUMMARY\n";
    PrintSeparator();
    
    std::cout << "  Total Gates:    " << report.totalGates << "\n";
    std::cout << "  Passed:         " << report.passedGates << "\n";
    std::cout << "  Failed:         " << report.failedGates << "\n";
    std::cout << "  Warnings:       " << report.warningGates << "\n";
    std::cout << "  Skipped:        " << report.skippedGates << "\n\n";
    
    PrintSeparator();
    std::cout << "SCORING\n";
    PrintSeparator();
    
    std::cout << "  Overall Score:  " << std::fixed << std::setprecision(1) << report.overallScore << "/100\n";
    std::cout << "  Release Status: ";
    
    if (report.releaseDecision == "APPROVED") {
        std::cout << "✓ APPROVED\n";
    } else if (report.releaseDecision == "CONDITIONAL") {
        std::cout << "⚠ CONDITIONAL\n";
    } else {
        std::cout << "✗ BLOCKED\n";
    }
    std::cout << "\n";
    
    if (!report.blockingIssues.empty()) {
        PrintSeparator();
        std::cout << "BLOCKING ISSUES\n";
        PrintSeparator();
        for (const auto& issue : report.blockingIssues) {
            std::cout << "  ✗ " << issue.gateId << ": " << issue.description << "\n";
        }
        std::cout << "\n";
    }
    
    if (!report.warnings.empty()) {
        PrintSeparator();
        std::cout << "WARNINGS\n";
        PrintSeparator();
        for (const auto& warning : report.warnings) {
            std::cout << "  ⚠ " << warning.gateId << ": " << warning.description << "\n";
        }
        std::cout << "\n";
    }
    
    if (!report.recommendations.empty()) {
        PrintSeparator();
        std::cout << "RECOMMENDATIONS\n";
        PrintSeparator();
        for (const auto& rec : report.recommendations) {
            std::cout << "  → " << rec << "\n";
        }
        std::cout << "\n";
    }
    
    if (report.hotpatchesApplied > 0) {
        PrintSeparator();
        std::cout << "HOTPATCH STATUS\n";
        PrintSeparator();
        std::cout << "  Applied: " << report.hotpatchesApplied << "\n";
        std::cout << "  Available: " << report.hotpatchesAvailable << "\n\n";
    }
}

int main() {
    PrintHeader("SWARM HOTPATCH VALIDATION FRAMEWORK DEMO");
    
    // Initialize hotpatcher
    SwarmHotpatcher& hotpatcher = SwarmHotpatcher::GetInstance();
    
    if (!hotpatcher.Initialize()) {
        std::cerr << "Failed to initialize SwarmHotpatcher\n";
        return 1;
    }
    
    std::cout << "✓ SwarmHotpatcher initialized\n";
    std::cout << "  Total gates registered: " << hotpatcher.GetTotalGateCount() << "\n\n";
    
    // =========================================================================
    // Test 1: Execute Individual Quality Gates (VAL-061 to VAL-070)
    // =========================================================================
    PrintHeader("TEST 1: QUALITY ATTRIBUTE GATES (VAL-061 to VAL-070)");
    
    std::cout << "Executing quality attribute validation gates...\n\n";
    
    auto qualityResults = hotpatcher.ExecuteGatesByType(ValidationGateType::PERFORMANCE_REGRESSION);
    auto memoryResults = hotpatcher.ExecuteGatesByType(ValidationGateType::MEMORY_REGRESSION);
    auto determinismResults = hotpatcher.ExecuteGatesByType(ValidationGateType::DETERMINISM);
    auto raceResults = hotpatcher.ExecuteGatesByType(ValidationGateType::RACE_CONDITION);
    auto hotpatchResults = hotpatcher.ExecuteGatesByType(ValidationGateType::HOTPATCH_VERIFICATION);
    auto ggufResults = hotpatcher.ExecuteGatesByType(ValidationGateType::GGUF_COMPATIBILITY);
    auto quantResults = hotpatcher.ExecuteGatesByType(ValidationGateType::QUANT_KERNEL);
    auto longContextResults = hotpatcher.ExecuteGatesByType(ValidationGateType::LONG_CONTEXT);
    auto agentResults = hotpatcher.ExecuteGatesByType(ValidationGateType::AGENT_STABILITY);
    auto releaseResults = hotpatcher.ExecuteGatesByType(ValidationGateType::RELEASE_CERTIFICATION);
    
    // Combine all results
    std::vector<ValidationResult> allQualityResults;
    allQualityResults.insert(allQualityResults.end(), qualityResults.begin(), qualityResults.end());
    allQualityResults.insert(allQualityResults.end(), memoryResults.begin(), memoryResults.end());
    allQualityResults.insert(allQualityResults.end(), determinismResults.begin(), determinismResults.end());
    allQualityResults.insert(allQualityResults.end(), raceResults.begin(), raceResults.end());
    allQualityResults.insert(allQualityResults.end(), hotpatchResults.begin(), hotpatchResults.end());
    allQualityResults.insert(allQualityResults.end(), ggufResults.begin(), ggufResults.end());
    allQualityResults.insert(allQualityResults.end(), quantResults.begin(), quantResults.end());
    allQualityResults.insert(allQualityResults.end(), longContextResults.begin(), longContextResults.end());
    allQualityResults.insert(allQualityResults.end(), agentResults.begin(), agentResults.end());
    allQualityResults.insert(allQualityResults.end(), releaseResults.begin(), releaseResults.end());
    
    PrintSeparator();
    std::cout << std::left << std::setw(12) << "Gate" << " | "
              << std::setw(10) << "Status" << " | "
              << std::setw(6) << "Score" << " | "
              << "Duration\n";
    PrintSeparator();
    
    for (const auto& result : allQualityResults) {
        PrintResult(result);
    }
    
    std::cout << std::endl;
    
    // =========================================================================
    // Test 2: Execute Master Gate
    // =========================================================================
    PrintHeader("TEST 2: MASTER GATE EXECUTION");
    
    std::cout << "Running complete validation suite...\n\n";
    
    MasterGateReport report = hotpatcher.ExecuteMasterGate();
    
    PrintMasterReport(report);
    
    // =========================================================================
    // Test 3: Hotpatch Management
    // =========================================================================
    PrintHeader("TEST 3: HOTPATCH MANAGEMENT");
    
    // Create a sample hotpatch
    ValidationHotpatch patch;
    patch.patchId = "HOTPATCH-001";
    patch.targetGate = "VAL-061";
    patch.description = "Fix token generation rate regression";
    patch.filePath = "src/inference/pipeline.cpp";
    patch.oldCode = "batch_size = 1;";
    patch.newCode = "batch_size = 4;";
    patch.confidence = 0.85f;
    patch.autoApply = true;
    patch.validated = false;
    patch.rollbackAvailable = true;
    
    std::cout << "Staging hotpatch...\n";
    hotpatcher.StageHotpatch(patch);
    std::cout << "  ✓ Hotpatch staged: " << patch.patchId << "\n";
    std::cout << "    Target: " << patch.targetGate << "\n";
    std::cout << "    Confidence: " << patch.confidence * 100 << "%\n";
    std::cout << "    Auto-apply: " << (patch.autoApply ? "Yes" : "No") << "\n\n";
    
    // Auto-apply hotpatches
    std::cout << "Auto-applying hotpatches above 80% confidence...\n";
    int applied = hotpatcher.AutoApplyHotpatches(0.8f);
    std::cout << "  ✓ Applied " << applied << " hotpatch(es)\n\n";
    
    // Show applied hotpatches
    auto appliedPatches = hotpatcher.GetAppliedHotpatches();
    if (!appliedPatches.empty()) {
        std::cout << "Applied hotpatches:\n";
        for (const auto& p : appliedPatches) {
            std::cout << "  - " << p.patchId << ": " << p.description << "\n";
        }
    }
    
    std::cout << std::endl;
    
    // =========================================================================
    // Test 4: Configuration
    // =========================================================================
    PrintHeader("TEST 4: CONFIGURATION");
    
    std::cout << "Current tolerances:\n";
    std::cout << "  Performance: " << hotpatcher.GetPerformanceTolerance() << "%\n";
    std::cout << "  Memory:      " << hotpatcher.GetMemoryTolerance() << "%\n";
    std::cout << "  Determinism: " << hotpatcher.GetDeterminismTolerance() << "%\n";
    std::cout << "  Auto-hotpatch threshold: " << hotpatcher.GetAutoHotpatchThreshold() * 100 << "%\n\n";
    
    // Update configuration
    std::cout << "Updating tolerances...\n";
    hotpatcher.SetPerformanceTolerance(3.0);
    hotpatcher.SetMemoryTolerance(4.0);
    std::cout << "  ✓ Performance tolerance: 3%\n";
    std::cout << "  ✓ Memory tolerance: 4%\n\n";
    
    // =========================================================================
    // Test 5: Statistics
    // =========================================================================
    PrintHeader("TEST 5: STATISTICS");
    
    std::cout << "Validation Statistics:\n";
    std::cout << "  Total gates:     " << hotpatcher.GetTotalGateCount() << "\n";
    std::cout << "  Executed:        " << hotpatcher.GetExecutedGateCount() << "\n";
    std::cout << "  Passed:          " << hotpatcher.GetPassedGateCount() << "\n";
    std::cout << "  Failed:          " << hotpatcher.GetFailedGateCount() << "\n";
    std::cout << "  Hotpatches:      " << hotpatcher.GetHotpatchCount() << "\n\n";
    
    // =========================================================================
    // Cleanup
    // =========================================================================
    PrintHeader("CLEANUP");
    
    std::cout << "Shutting down SwarmHotpatcher...\n";
    hotpatcher.Shutdown();
    std::cout << "  ✓ Shutdown complete\n\n";
    
    PrintSeparator();
    std::cout << "DEMO COMPLETE\n";
    PrintSeparator();
    
    return 0;
}
