// RawrXD-Script Golden Master Database
// Stores known-good execution fingerprints for regression detection
// Phase: Baseline Generation for Self-Diagnosing Engine

#pragma once

#include "trace_collector_masm.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <utility>
#include <cstdint>
#include <cstdio>

namespace RawrXD {
namespace Script {

// Golden master entry for a single test
struct GoldenMasterEntry {
    std::string testName;                    // Test identifier (e.g., "test_addition")
    std::string testCategory;                // Category (e.g., "arithmetic", "control_flow")
    ExecutionFingerprint fingerprint;        // Known-good execution trace hash
    uint32_t expectedEventCount;             // Expected number of trace events
    uint32_t tolerancePercent;               // Allowed deviation (0 = exact match)
    uint64_t timestamp;                      // When this master was sealed
    std::string description;                 // Human-readable description
    
    GoldenMasterEntry() 
        : expectedEventCount(0), tolerancePercent(0), timestamp(0) {}
};

// Comparison result between current run and golden master
struct FingerprintComparison {
    enum class Status {
        Match,              // Fingerprints are identical
        WithinTolerance,    // Within allowed deviation
        Mismatch,           // Different execution path
        EventCountMismatch, // Same fingerprint but different event count
        MissingMaster,      // No golden master exists for this test
        Error               // Comparison failed
    };
    
    Status status;
    ExecutionFingerprint currentFingerprint;
    ExecutionFingerprint expectedFingerprint;
    uint32_t currentEventCount;
    uint32_t expectedEventCount;
    uint32_t hammingDistance;                // Bit difference between fingerprints
    double similarityScore;                  // 0.0 - 1.0 similarity
    std::string diagnosticMessage;           // Human-readable explanation
    
    FingerprintComparison() 
        : status(Status::Error), currentEventCount(0), expectedEventCount(0),
          hammingDistance(0), similarityScore(0.0) {}
    
    bool IsPass() const {
        return status == Status::Match || status == Status::WithinTolerance;
    }
    
    bool IsFail() const {
        return !IsPass();
    }
};

// Golden Master Database
class GoldenMasterDB {
public:
    // Initialize/load the database from disk
    static bool Initialize(const std::string& dbPath = "golden_masters.db");
    
    // Seal a new golden master (record current execution as canonical)
    static bool SealMaster(
        const std::string& testName,
        const std::string& category,
        const ExecutionFingerprint& fingerprint,
        uint32_t eventCount,
        const std::string& description = "",
        uint32_t tolerancePercent = 0);
    
    // Compare current execution against stored master
    static FingerprintComparison CompareAgainstMaster(
        const std::string& testName,
        const ExecutionFingerprint& currentFingerprint,
        uint32_t currentEventCount);
    
    // Get master entry for a test
    static bool GetMaster(const std::string& testName, GoldenMasterEntry& outEntry);
    
    // Check if master exists
    static bool HasMaster(const std::string& testName);
    
    // Delete a master entry
    static bool DeleteMaster(const std::string& testName);
    
    // List all masters
    static std::vector<GoldenMasterEntry> ListMasters();
    
    // List masters by category
    static std::vector<GoldenMasterEntry> ListMastersByCategory(const std::string& category);
    
    // Save database to disk
    static bool SaveToDisk(const std::string& dbPath = "golden_masters.db");
    
    // Load database from disk
    static bool LoadFromDisk(const std::string& dbPath = "golden_masters.db");
    
    // Clear all masters
    static void Clear();
    
    // Get database statistics
    static size_t GetMasterCount();
    static size_t GetCategoryCount();
    
    // Export to JSON for inspection
    static bool ExportToJSON(const std::string& jsonPath);
    
    // Import from JSON
    static bool ImportFromJSON(const std::string& jsonPath);
    
private:
    static std::unordered_map<std::string, GoldenMasterEntry> s_masters;
    static bool s_initialized;
    static std::string s_dbPath;
};

// Test harness for automated regression detection
class RegressionTestHarness {
public:
    struct TestResult {
        std::string testName;
        bool passed;
        FingerprintComparison comparison;
        uint64_t executionTimeUs;            // Microseconds
        std::string errorMessage;
    };
    
    struct RunSummary {
        size_t totalTests;
        size_t passed;
        size_t failed;
        size_t newTests;                     // Tests without masters
        size_t errors;
        uint64_t totalExecutionTimeUs;
        std::vector<TestResult> results;
    };
    
    // Run a single test and compare against master
    static TestResult RunTest(
        const std::string& testName,
        std::function<void()> testFunction);
    
    // Run all tests in the corpus
    static RunSummary RunAllTests(
        const std::vector<std::pair<std::string, std::function<void()>>>& tests);
    
    // Generate HTML report
    static bool GenerateHTMLReport(const RunSummary& summary, const std::string& outputPath);
    
    // Generate console report
    static void GenerateConsoleReport(const RunSummary& summary);
    
    // Seal all current test results as new masters
    static bool SealAllAsMasters(const RunSummary& summary);
};

// Utility functions
namespace GoldenMasterUtils {
    // Calculate Hamming distance between two fingerprints
    uint32_t CalculateHammingDistance(
        const ExecutionFingerprint& a, 
        const ExecutionFingerprint& b);
    
    // Calculate similarity score (0.0 - 1.0)
    double CalculateSimilarity(
        const ExecutionFingerprint& a,
        const ExecutionFingerprint& b);
    
    // Check if fingerprints are within tolerance
    bool IsWithinTolerance(
        const ExecutionFingerprint& current,
        const ExecutionFingerprint& expected,
        uint32_t tolerancePercent);
    
    // Generate timestamp
    uint64_t GetCurrentTimestamp();
    
    // Format fingerprint for display
    std::string FormatFingerprint(const ExecutionFingerprint& fp);
    
    // Parse fingerprint from string
    bool ParseFingerprint(const std::string& str, ExecutionFingerprint& fp);
}

} // namespace Script
} // namespace RawrXD
