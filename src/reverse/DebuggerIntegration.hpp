#pragma once
#include "ComprehensivePatternGenerator.hpp"
#include <windows.h>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <set>

namespace RawrXD::Reverse {

// === Debugger Event Types ===

enum class DebugEventType {
    PROCESS_ATTACHED,
    PROCESS_DETACHED,
    THREAD_CREATED,
    THREAD_EXITED,
    MODULE_LOADED,
    MODULE_UNLOADED,
    BREAKPOINT_HIT,
    PATTERN_MATCHED,
    MEMORY_ACCESS_VIOLATION,
    SINGLE_STEP,
    EXCEPTION,
    CUSTOM
};

// === Memory Region Info ===

struct MemoryRegion {
    uintptr_t base_address;
    size_t size;
    DWORD protection;
    DWORD state;
    DWORD type;
    std::string module_name;
    bool is_executable;
    bool is_readable;
    bool is_writable;
    
    // Pattern analysis results
    std::vector<ComprehensivePattern> discovered_patterns;
    double region_entropy;
    bool contains_code;
    bool contains_data;
};

// === Breakpoint Types ===

enum class BreakpointType {
    SOFTWARE_INT3,      // 0xCC
    HARDWARE_DR,      // Debug registers
    MEMORY_PAGE,      // Page guard
    PATTERN_MATCH,    // Pattern-based
    FUNCTION_ENTRY,   // Function prologue
    FUNCTION_EXIT,    // Function epilogue
    API_CALL,         // IAT hook
    INSTRUCTION_TRACE // Single-step
};

struct Breakpoint {
    uintptr_t address;
    BreakpointType type;
    std::string id;
    std::string description;
    bool enabled;
    uint8_t original_byte;  // For software breakpoints
    std::vector<uint8_t> pattern;  // For pattern breakpoints
    std::function<void(const DebugEvent&)> callback;
    size_t hit_count;
    size_t skip_count;
};

// === Debug Event ===

struct DebugEvent {
    DebugEventType type;
    DWORD process_id;
    DWORD thread_id;
    uintptr_t address;
    std::string module_name;
    std::string description;
    
    // Pattern match info
    std::vector<ComprehensivePattern> matched_patterns;
    std::vector<uint8_t> context_bytes;
    size_t context_offset;
    
    // Exception info
    DWORD exception_code;
    uintptr_t exception_address;
    
    // Timestamp
    uint64_t timestamp;
    uint64_t cycles;
};

// === Live Analysis Results ===

struct LiveAnalysisResult {
    uintptr_t address;
    std::vector<uint8_t> bytes;
    std::vector<ComprehensivePattern> matched_patterns;
    std::string disassembly;
    std::string function_name;
    std::string module_name;
    bool is_function_start;
    bool is_function_end;
    std::vector<std::string> call_targets;
    std::vector<std::string> jump_targets;
    double confidence;
};

// === Process Info ===

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string path;
    bool is_64bit;
    std::vector<MemoryRegion> memory_regions;
    std::vector<std::string> loaded_modules;
    size_t total_memory;
    size_t private_memory;
};

// === Debugger Integration Class ===

class DebuggerIntegration {
public:
    DebuggerIntegration();
    ~DebuggerIntegration();

    // === Process Management ===
    
    bool attachToProcess(DWORD pid);
    bool attachToProcess(const std::string& process_name);
    bool launchProcess(const std::string& executable_path, const std::string& arguments = "");
    bool detach();
    bool terminateProcess();
    
    // === Memory Operations ===
    
    std::vector<MemoryRegion> enumerateMemoryRegions();
    bool readMemory(uintptr_t address, std::vector<uint8_t>& buffer, size_t size);
    bool writeMemory(uintptr_t address, const std::vector<uint8_t>& buffer);
    bool protectMemory(uintptr_t address, size_t size, DWORD protection);
    
    // === Pattern Scanning in Memory ===
    
    std::vector<LiveAnalysisResult> scanMemoryForPatterns(
        const std::vector<ComprehensivePattern>& patterns,
        DWORD memory_protection = PAGE_EXECUTE_READ
    );
    
    std::vector<LiveAnalysisResult> scanRegionForPatterns(
        const MemoryRegion& region,
        const std::vector<ComprehensivePattern>& patterns
    );
    
    // Discover patterns live in memory
    std::vector<ComprehensivePattern> discoverPatternsInMemory(
        size_t min_frequency = 3,
        size_t min_pattern_length = 4,
        size_t max_pattern_length = 64
    );
    
    // === Breakpoint Management ===
    
    std::string setSoftwareBreakpoint(uintptr_t address, std::function<void(const DebugEvent&)> callback = nullptr);
    std::string setHardwareBreakpoint(uintptr_t address, BreakpointType type = BreakpointType::HARDWARE_DR);
    std::string setPatternBreakpoint(const std::vector<uint8_t>& pattern, std::function<void(const DebugEvent&)> callback = nullptr);
    std::string setFunctionEntryBreakpoint(const std::string& function_name);
    std::string setFunctionExitBreakpoint(const std::string& function_name);
    std::string setAPICallBreakpoint(const std::string& api_name);
    
    bool removeBreakpoint(const std::string& breakpoint_id);
    bool enableBreakpoint(const std::string& breakpoint_id);
    bool disableBreakpoint(const std::string& breakpoint_id);
    
    // === Execution Control ===
    
    bool continueExecution();
    bool stepInto();
    bool stepOver();
    bool stepOut();
    bool runUntil(uintptr_t address);
    bool runUntilPattern(const std::vector<uint8_t>& pattern);
    
    // === Event Loop ===
    
    void startEventLoop();
    void stopEventLoop();
    bool isEventLoopRunning() const;
    
    // Set callback for specific event types
    void setEventCallback(DebugEventType type, std::function<void(const DebugEvent&)> callback);
    void setDefaultCallback(std::function<void(const DebugEvent&)> callback);
    
    // === Real-time Analysis ===
    
    LiveAnalysisResult analyzeAddress(uintptr_t address, size_t context_size = 64);
    std::vector<LiveAnalysisResult> analyzeFunction(uintptr_t function_address);
    std::vector<LiveAnalysisResult> traceExecution(size_t instruction_count);
    
    // === Pattern Generator Integration ===
    
    void setPatternGenerator(std::shared_ptr<ComprehensivePatternGenerator> generator);
    std::vector<ComprehensivePattern> generatePatternsFromMemory(
        uintptr_t address,
        size_t size,
        const GenerationRequest& request = GenerationRequest()
    );
    
    // Auto-generate and match patterns
    std::vector<LiveAnalysisResult> autoPatternMatch(
        const std::vector<uint8_t>& source_bytes,
        uintptr_t search_address = 0,
        size_t search_size = 0
    );
    
    // === Export/Import ===
    
    bool exportMemoryToFile(uintptr_t address, size_t size, const std::string& file_path);
    bool importPatternsFromFile(const std::string& file_path);
    bool saveSession(const std::string& session_path);
    bool loadSession(const std::string& session_path);
    
    // === Information ===
    
    ProcessInfo getProcessInfo() const;
    std::vector<Breakpoint> getBreakpoints() const;
    std::vector<std::string> getLoadedModules() const;
    uintptr_t resolveSymbol(const std::string& symbol_name);
    std::string getSymbolName(uintptr_t address);
    
    // === Status ===
    
    bool isAttached() const;
    DWORD getProcessId() const;
    HANDLE getProcessHandle() const;
    HANDLE getThreadHandle() const;
    
    // === Statistics ===
    
    struct DebugStats {
        size_t events_processed;
        size_t breakpoints_hit;
        size_t patterns_matched;
        size_t memory_regions_scanned;
        size_t bytes_analyzed;
        size_t exceptions_caught;
        double average_scan_time_ms;
        double total_runtime_seconds;
    };
    
    DebugStats getStats() const;
    void resetStats();

private:
    // Internal state
    HANDLE process_handle_;
    HANDLE thread_handle_;
    DWORD process_id_;
    DWORD thread_id_;
    bool is_attached_;
    bool is_64bit_;
    bool event_loop_running_;
    
    // Pattern generator
    std::shared_ptr<ComprehensivePatternGenerator> pattern_generator_;
    
    // Breakpoints
    std::unordered_map<std::string, Breakpoint> breakpoints_;
    size_t breakpoint_counter_;
    
    // Event callbacks
    std::unordered_map<DebugEventType, std::function<void(const DebugEvent&)>> event_callbacks_;
    std::function<void(const DebugEvent&)> default_callback_;
    
    // Memory cache
    std::unordered_map<uintptr_t, std::vector<uint8_t>> memory_cache_;
    
    // Statistics
    DebugStats stats_;
    std::chrono::steady_clock::time_point start_time_;
    
    // Internal methods
    bool setDebugPrivilege();
    bool waitForDebugEvent(DEBUG_EVENT& event, DWORD timeout_ms = INFINITE);
    bool handleDebugEvent(const DEBUG_EVENT& event);
    bool setSoftwareBreakpointInternal(uintptr_t address, Breakpoint& bp);
    bool removeSoftwareBreakpointInternal(const Breakpoint& bp);
    bool setHardwareBreakpointInternal(uintptr_t address, int dr_index);
    bool removeHardwareBreakpointInternal(int dr_index);
    
    std::vector<uint8_t> readMemoryInternal(uintptr_t address, size_t size);
    bool writeMemoryInternal(uintptr_t address, const std::vector<uint8_t>& data);
    
    std::string generateBreakpointId();
    DebugEvent createDebugEvent(const DEBUG_EVENT& raw_event);
    
    // Pattern matching
    std::vector<ComprehensivePattern> matchPatternsAtAddress(
        uintptr_t address,
        const std::vector<uint8_t>& data,
        const std::vector<ComprehensivePattern>& patterns
    );
    
    // Disassembly (placeholder - would use Zydis or similar)
    std::string disassembleAt(uintptr_t address, const std::vector<uint8_t>& bytes);
};

} // namespace RawrXD::Reverse
