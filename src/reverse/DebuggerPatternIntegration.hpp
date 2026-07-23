// ============================================================================
// DebuggerPatternIntegration.hpp - Debugger Integration for Pattern Generator
// ============================================================================

#pragma once

#include "ComprehensivePatternGenerator.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

namespace RawrXD::Reverse {

// Forward declarations for debugger types
struct DebugContext;
struct MemoryRegion;
struct Breakpoint;

// ============================================================================
// Debugger Pattern Integration Types
// ============================================================================

enum class DebuggerState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ATTACHED,
    RUNNING,
    PAUSED,
    ERROR
};

enum class MemoryAccessType {
    READ,
    WRITE,
    EXECUTE,
    ALL
};

struct MemoryRegionInfo {
    uint64_t base_address;
    size_t size;
    std::string name;
    MemoryAccessType access;
    bool is_executable;
    bool is_writable;
    bool is_readable;
};

struct PatternMatchInMemory {
    std::string pattern_id;
    uint64_t address;
    size_t length;
    PatternType type;
    double confidence;
    std::vector<uint8_t> matched_bytes;
    std::string region_name;
    bool is_hotspot;  // Frequently accessed
};

struct BreakpointPattern {
    uint64_t address;
    std::string pattern_id;
    std::string condition;
    bool enabled;
    size_t hit_count;
    std::function<void(const PatternMatchInMemory&)> on_hit;
};

struct LivePatternAnalysis {
    std::vector<PatternMatchInMemory> active_matches;
    std::vector<MemoryRegionInfo> scanned_regions;
    size_t total_bytes_scanned;
    size_t patterns_found;
    double scan_duration_ms;
    uint64_t timestamp;
};

struct DebuggerConfig {
    std::string target_process_name;
    uint32_t target_pid;
    bool auto_attach;
    bool scan_on_attach;
    size_t min_pattern_length;
    size_t max_pattern_length;
    double min_confidence;
    bool enable_breakpoints;
    bool enable_hotspot_detection;
    size_t hotspot_threshold;
};

// ============================================================================
// Debugger Pattern Integration Class
// ============================================================================

class DebuggerPatternIntegration {
public:
    DebuggerPatternIntegration();
    ~DebuggerPatternIntegration();

    // Connection management
    bool connectToDebugger(const std::string& debugger_path);
    bool connectToProcess(uint32_t pid);
    bool connectToProcess(const std::string& process_name);
    bool disconnect();
    bool isConnected() const;
    DebuggerState getState() const;

    // Pattern scanning in memory
    std::vector<PatternMatchInMemory> scanMemoryRegion(
        uint64_t base_address,
        size_t size,
        const std::vector<ComprehensivePattern>& patterns);
    
    std::vector<PatternMatchInMemory> scanAllMemoryRegions(
        const std::vector<ComprehensivePattern>& patterns);
    
    std::vector<PatternMatchInMemory> scanExecutableRegions(
        const std::vector<ComprehensivePattern>& patterns);
    
    // Live analysis
    LivePatternAnalysis performLiveAnalysis(
        const std::vector<ComprehensivePattern>& patterns,
        size_t duration_ms = 1000);
    
    // Breakpoint management
    bool setPatternBreakpoint(
        uint64_t address,
        const std::string& pattern_id,
        const std::string& condition = "");
    
    bool removePatternBreakpoint(uint64_t address);
    void clearAllBreakpoints();
    std::vector<BreakpointPattern> getActiveBreakpoints() const;

    // Hotspot detection
    std::vector<PatternMatchInMemory> detectHotspots(
        size_t threshold = 10);
    
    // Memory region management
    std::vector<MemoryRegionInfo> enumerateMemoryRegions();
    MemoryRegionInfo getMemoryRegionInfo(uint64_t address) const;
    
    // Pattern injection (for testing)
    bool injectPatternAtAddress(
        uint64_t address,
        const std::vector<uint8_t>& pattern_bytes);
    
    // Export results
    std::string exportScanResults(const std::vector<PatternMatchInMemory>& matches);
    bool exportToDebuggerFormat(
        const std::vector<PatternMatchInMemory>& matches,
        const std::string& output_path);

    // Callbacks
    void setOnPatternFound(std::function<void(const PatternMatchInMemory&)> callback);
    void setOnBreakpointHit(std::function<void(const BreakpointPattern&)> callback);
    void setOnMemoryAccess(std::function<void(uint64_t, size_t, MemoryAccessType)> callback);

    // Configuration
    void setConfig(const DebuggerConfig& config);
    DebuggerConfig getConfig() const;

    // Statistics
    struct IntegrationStats {
        size_t total_scans;
        size_t total_matches_found;
        size_t total_breakpoints_hit;
        size_t total_hotspots_detected;
        double total_scan_time_ms;
        size_t memory_regions_scanned;
    };
    IntegrationStats getStats() const;
    void resetStats();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Pattern-Aware Debugger Commands
// ============================================================================

class PatternDebuggerCommands {
public:
    // Command handlers
    static std::string cmdPatternScan(
        const std::vector<std::string>& args,
        DebuggerPatternIntegration* integration);
    
    static std::string cmdPatternFind(
        const std::vector<std::string>& args,
        DebuggerPatternIntegration* integration);
    
    static std::string cmdPatternBreakpoint(
        const std::vector<std::string>& args,
        DebuggerPatternIntegration* integration);
    
    static std::string cmdPatternHotspots(
        const std::vector<std::string>& args,
        DebuggerPatternIntegration* integration);
    
    static std::string cmdPatternExport(
        const std::vector<std::string>& args,
        DebuggerPatternIntegration* integration);
    
    static std::string cmdPatternInfo(
        const std::vector<std::string>& args,
        const std::vector<ComprehensivePattern>& patterns);
    
    static std::string cmdPatternCompare(
        const std::vector<std::string>& args,
        const ComprehensivePattern& a,
        const ComprehensivePattern& b);

    // Help text
    static std::string getHelpText();
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string formatAddress(uint64_t address);
std::string formatBytes(const std::vector<uint8_t>& bytes, size_t max_len = 16);
std::string formatPatternType(PatternType type);

} // namespace RawrXD::Reverse
