//============================================================================
// nevm_replay_harness.hpp
// RawrXD N-EVM - Deterministic Replay Harness
// Records execution sequences for debugging and regression bisection
//============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <json/json.h>
#include <fstream>
#include <chrono>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Execution Event Types
//============================================================================

enum class ExecutionEventType {
    KernelLaunch,           // GPU kernel execution
    MemoryAllocation,       // Memory alloc/free
    KVCacheOperation,       // KV cache read/write/migrate
    TensorOperation,        // Tensor creation/destruction
    RandomNumber,           // RNG state
    Synchronization,        // Device synchronization
    MathModeChange,         // Math mode switch
    ProfileSwitch,          // Performance profile change
    Checkpoint              // Manual checkpoint
};

std::string ExecutionEventTypeToString(ExecutionEventType type);
ExecutionEventType ExecutionEventTypeFromString(const std::string& str);

//============================================================================
// Execution Event
//============================================================================

struct ExecutionEvent {
    uint64_t sequence_id;           // Global sequence number
    ExecutionEventType type;
    uint64_t timestamp_ns;          // Nanosecond timestamp
    std::string kernel_name;        // For kernel events
    std::vector<uint8_t> data;     // Event-specific data
    uint64_t checksum;              // Data integrity
    
    // For KV cache operations
    struct KVCacheInfo {
        uint64_t page_id;
        uint32_t layer_id;
        uint32_t sequence_pos;
        std::string operation;  // "read", "write", "migrate", "evict"
    } kv_info;
    
    // For memory operations
    struct MemoryInfo {
        uint64_t address;
        size_t size;
        std::string pool;  // "device", "host", "unified"
    } mem_info;
    
    // For tensor operations
    struct TensorInfo {
        std::string name;
        std::vector<size_t> shape;
        std::string dtype;
    } tensor_info;
    
    Json::Value ToJSON() const;
    static ExecutionEvent FromJSON(const Json::Value& json);
};

//============================================================================
// Execution Sequence
//============================================================================

class ExecutionSequence {
public:
    ExecutionSequence() : next_sequence_id_(0) {}
    
    // Record an event
    void RecordEvent(const ExecutionEvent& event);
    
    // Get event by sequence ID
    const ExecutionEvent* GetEvent(uint64_t sequence_id) const;
    
    // Get all events
    const std::vector<ExecutionEvent>& GetEvents() const { return events_; }
    
    // Get events by type
    std::vector<ExecutionEvent> GetEventsByType(ExecutionEventType type) const;
    
    // Get events in range
    std::vector<ExecutionEvent> GetEventsInRange(uint64_t start, uint64_t end) const;
    
    // Find divergence point between two sequences
    static uint64_t FindDivergencePoint(const ExecutionSequence& a, 
                                        const ExecutionSequence& b);
    
    // Export to file
    void SaveToFile(const std::string& path) const;
    static ExecutionSequence LoadFromFile(const std::string& path);
    
    // Statistics
    struct Stats {
        size_t total_events;
        size_t kernel_events;
        size_t memory_events;
        size_t kv_events;
        uint64_t duration_ns;
        std::map<std::string, size_t> events_by_kernel;
    };
    
    Stats GetStats() const;

private:
    std::vector<ExecutionEvent> events_;
    uint64_t next_sequence_id_;
    
    uint64_t GenerateChecksum(const std::vector<uint8_t>& data) const;
};

//============================================================================
// State Snapshot
//============================================================================

struct StateSnapshot {
    uint64_t sequence_id;           // Point in execution
    std::string timestamp;
    
    // Memory state
    struct MemoryState {
        uint64_t total_allocated;
        uint64_t peak_allocated;
        std::map<uint64_t, size_t> active_allocations;
    } memory;
    
    // KV cache state
    struct KVCacheState {
        size_t total_pages;
        size_t resident_pages;
        size_t migrated_pages;
        std::vector<uint64_t> active_page_ids;
    } kv_cache;
    
    // Tensor registry
    struct TensorState {
        size_t active_tensors;
        size_t total_memory;
        std::map<std::string, size_t> tensor_sizes;
    } tensors;
    
    // RNG state
    struct RNGState {
        uint64_t seed;
        uint64_t sequence_position;
        std::vector<uint8_t> state_data;
    } rng;
    
    Json::Value ToJSON() const;
    static StateSnapshot FromJSON(const Json::Value& json);
};

//============================================================================
// Replay Harness
//============================================================================

class ReplayHarness {
public:
    struct Config {
        bool record_kernels = true;
        bool record_memory = true;
        bool record_kv_cache = true;
        bool record_tensors = true;
        bool record_rng = true;
        bool auto_checkpoint = true;
        uint64_t checkpoint_interval_ms = 60000;  // 1 minute
    };
    
    ReplayHarness(const Config& config = Config()) : config_(config), is_recording_(false) {}
    
    // Recording control
    void StartRecording();
    void StopRecording();
    bool IsRecording() const { return is_recording_; }
    
    // Event recording
    void RecordKernelLaunch(const std::string& kernel_name, 
                           const std::vector<uint8_t>& params);
    void RecordMemoryAllocation(uint64_t address, size_t size, const std::string& pool);
    void RecordMemoryFree(uint64_t address);
    void RecordKVCacheOperation(uint64_t page_id, uint32_t layer_id,
                                uint32_t seq_pos, const std::string& operation);
    void RecordTensorOperation(const std::string& name, 
                              const std::vector<size_t>& shape,
                              const std::string& dtype,
                              const std::string& operation);
    void RecordRNGState(uint64_t seed, uint64_t position);
    void RecordSynchronization();
    void RecordMathModeChange(MathMode old_mode, MathMode new_mode);
    void RecordProfileSwitch(const std::string& old_profile, 
                            const std::string& new_profile);
    void RecordCheckpoint(const std::string& label);
    
    // State snapshots
    void CaptureSnapshot(const std::string& label = "");
    StateSnapshot GetLastSnapshot() const;
    std::vector<StateSnapshot> GetSnapshots() const { return snapshots_; }
    
    // Replay control
    void LoadSequence(const ExecutionSequence& sequence);
    bool ReplayNextEvent();
    bool ReplayToCheckpoint(const std::string& label);
    bool ReplayToSequenceId(uint64_t sequence_id);
    void ResetReplay();
    
    // Comparison
    struct ComparisonResult {
        bool identical;
        uint64_t first_divergence;
        std::string divergence_type;
        std::string expected_value;
        std::string actual_value;
    };
    
    ComparisonResult CompareWithRecording(const ExecutionSequence& current) const;
    
    // Export/Import
    void SaveRecording(const std::string& path) const;
    void LoadRecording(const std::string& path);
    
    // Analysis
    std::vector<std::string> AnalyzeDivergence(const ExecutionSequence& expected,
                                                const ExecutionSequence& actual) const;
    
    // Bisection support
    struct BisectionPoint {
        uint64_t sequence_id;
        bool state_matches;
        std::string description;
    };
    
    std::vector<BisectionPoint> Bisect(const ExecutionSequence& good,
                                       const ExecutionSequence& bad) const;

private:
    Config config_;
    bool is_recording_;
    ExecutionSequence sequence_;
    std::vector<StateSnapshot> snapshots_;
    
    size_t replay_position_;
    std::map<std::string, uint64_t> checkpoint_map_;
    
    uint64_t GetTimestamp() const;
    void AutoCheckpoint();
};

//============================================================================
// Regression Bisector
//============================================================================

class RegressionBisector {
public:
    struct BisectionResult {
        uint64_t first_bad_sequence;
        ExecutionEvent bad_event;
        std::vector<ExecutionEvent> context_before;  // 10 events before
        std::vector<ExecutionEvent> context_after;   // 10 events after
        std::string root_cause_analysis;
    };
    
    // Bisect between known good and bad recordings
    static BisectionResult Bisect(const std::string& good_recording_path,
                                   const std::string& bad_recording_path);
    
    // Automated bisection with validation function
    template<typename ValidateFn>
    static BisectionResult AutomatedBisect(ValidateFn validate,
                                             const ExecutionSequence& baseline,
                                             uint64_t max_sequence = 0);

private:
    static bool ValidateEvent(const ExecutionEvent& event);
    static std::string AnalyzeRootCause(const ExecutionEvent& event);
};

} // namespace NEVM
} // namespace RawrXD
