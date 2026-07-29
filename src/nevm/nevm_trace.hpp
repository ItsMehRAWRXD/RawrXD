//============================================================================
// nevm_trace.hpp
// RawrXD N-EVM Deterministic Replay System
// Capture and replay execution traces for debugging and benchmarking
//============================================================================

#pragma once

#include "nevm_isa.hpp"
#include "nevm_residency.hpp"
#include <fstream>
#include <chrono>

namespace RawrXD {
namespace NEVM {

using ISA::VirtualTensorAddress;
using ISA::PrecisionMode;
using ISA::ResidencyTarget;

//============================================================================
// Trace Event Types
//============================================================================

enum class TraceEventType : uint8_t {
    TOKEN_START = 0,           // New token generation begins
    TOKEN_END = 1,             // Token generation completes
    LAYER_START = 2,           // Layer execution begins
    LAYER_END = 3,             // Layer execution completes
    KERNEL_CALL = 4,           // Kernel invocation
    PRECISION_SELECT = 5,      // Precision controller decision
    RESIDENCY_TRANSITION = 6,    // Block residency state change
    PREFETCH_START = 7,        // Prefetch initiated
    PREFETCH_COMPLETE = 8,     // Prefetch finished
    MEMORY_ACCESS = 9,         // Tensor memory access
    TLB_HIT = 10,              // TLB cache hit
    TLB_MISS = 11,             // TLB cache miss
    STALL_CYCLE = 12,          // Pipeline stall
    ERROR_METRIC = 13,         // Quantization error recorded
    SAMPLING = 14              // Token sampling event
};

const char* TraceEventTypeToString(TraceEventType type);

//============================================================================
// Base Trace Event
//============================================================================

struct TraceEvent {
    uint64_t timestamp_ns;       // Nanosecond timestamp
    uint64_t token_id;         // Which token generation
    uint32_t layer_id;         // Which layer (if applicable)
    TraceEventType type;
    uint32_t thread_id;        // For multi-threaded execution
    
    TraceEvent() 
        : timestamp_ns(0)
        , token_id(0)
        , layer_id(0)
        , type(TraceEventType::TOKEN_START)
        , thread_id(0)
    {}
};

//============================================================================
// Specialized Trace Events
//============================================================================

struct TokenStartEvent : TraceEvent {
    uint32_t input_token_id;
    uint64_t sequence_position;
    float temperature;
    float top_p;
    uint32_t top_k;
};

struct TokenEndEvent : TraceEvent {
    uint32_t output_token_id;
    float token_probability;
    float generation_latency_ms;
    uint64_t memory_used_bytes;
};

struct LayerStartEvent : TraceEvent {
    uint32_t layer_id;
    PrecisionMode layer_precision;  // Dominant precision for layer
    uint64_t working_set_bytes;      // Memory active at layer start
};

struct LayerEndEvent : TraceEvent {
    uint32_t layer_id;
    float layer_latency_ms;
    uint32_t precision_switches;     // Number of precision changes in layer
};

struct KernelCallEvent : TraceEvent {
    char kernel_name[64];
    VirtualTensorAddress input_vta;
    VirtualTensorAddress output_vta;
    PrecisionMode input_precision;
    PrecisionMode output_precision;
    float kernel_latency_ms;
    uint64_t flops_executed;
};

struct PrecisionSelectEvent : TraceEvent {
    VirtualTensorAddress vta;
    SubLayerBlockID block_id;        // Granular block identification
    PrecisionMode selected_precision;
    PrecisionMode previous_precision;
    float importance_score;
    float predicted_error;
    float memory_pressure;
    float latency_budget_ms;
    char reason[256];                  // Why this precision was selected
};

struct ResidencyTransitionEvent : TraceEvent {
    VirtualTensorAddress vta;
    ResidencyState old_state;
    ResidencyState new_state;
    PrecisionMode old_format;
    PrecisionMode new_format;
    float transition_latency_ms;
    bool blocking;                   // Did this stall the pipeline?
};

struct PrefetchEvent : TraceEvent {
    VirtualTensorAddress vta;
    PrecisionMode target_precision;
    ResidencyTarget target_tier;
    uint64_t prefetch_start_ns;
    uint64_t prefetch_end_ns;
    bool hit;                        // Was already resident?
    bool used;                     // Was prefetched data accessed?
};

struct MemoryAccessEvent : TraceEvent {
    VirtualTensorAddress vta;
    ResidencyTarget tier_accessed;   // VRAM, RAM, etc.
    size_t bytes_read;
    size_t bytes_written;
    bool was_compressed;             // Had to decompress?
};

struct TLBEvent : TraceEvent {
    VirtualTensorAddress vta;
    uint64_t virtual_address;
    uint64_t physical_address;
    bool hit;
    uint64_t cache_line;
};

struct StallCycleEvent : TraceEvent {
    uint64_t stall_duration_ns;
    char reason[128];                // Why stalled (e.g., "PREFETCH_WAIT")
    VirtualTensorAddress waiting_for; // What we were waiting for
};

struct ErrorMetricEvent : TraceEvent {
    VirtualTensorAddress vta;
    PrecisionMode format_used;
    float max_error;
    float mean_error;
    float std_error;
    uint32_t sample_count;
};

struct SamplingEvent : TraceEvent {
    float temperature;
    float* logits;                   // Pointer to logits (not stored in trace)
    uint32_t vocab_size;
    uint32_t selected_token;
    float selected_probability;
    float* top_k_probs;              // Top-k probabilities
    uint32_t* top_k_tokens;
    uint32_t k;
};

//============================================================================
// Precision Map Snapshot
// Captures complete precision assignment at a point in time
//============================================================================

struct PrecisionMapSnapshot {
    uint64_t timestamp_ns;
    uint64_t token_id;
    uint32_t layer_id;
    
    // Block-level precision assignments
    struct BlockPrecision {
        SubLayerBlockID block_id;
        PrecisionMode precision;
        float importance;
    };
    std::vector<BlockPrecision> block_precisions;
    
    // Summary statistics
    std::map<PrecisionMode, uint32_t> precision_distribution;
    float effective_bits_per_param;
    size_t total_memory_bytes;
};

//============================================================================
// Residency Map Snapshot
// Captures complete residency state at a point in time
//============================================================================

struct ResidencyMapSnapshot {
    uint64_t timestamp_ns;
    
    struct BlockResidency {
        VirtualTensorAddress vta;
        ResidencyState state;
        PrecisionMode format;
        ResidencyTarget tier;
        uint64_t last_access_tick;
        uint64_t access_count;
    };
    std::vector<BlockResidency> block_residencies;
    
    // Summary by state
    std::map<ResidencyState, uint32_t> state_distribution;
    size_t total_resident_bytes;
    size_t total_compressed_bytes;
    float memory_pressure;
};

//============================================================================
// Execution Trace
// Complete trace of a token generation
//============================================================================

struct TokenExecutionTrace {
    uint64_t token_id;
    uint32_t input_token;
    uint32_t output_token;
    
    // Timing
    uint64_t start_ns;
    uint64_t end_ns;
    float total_latency_ms;
    
    // Events
    std::vector<std::unique_ptr<TraceEvent>> events;
    
    // Snapshots
    std::vector<PrecisionMapSnapshot> precision_snapshots;
    std::vector<ResidencyMapSnapshot> residency_snapshots;
    
    // Summary
    uint32_t num_layers_executed;
    uint32_t num_kernels_called;
    uint32_t num_precision_switches;
    uint32_t num_stall_cycles;
    uint64_t memory_peak_bytes;
    float prefetch_hit_rate;
};

//============================================================================
// Trace Recorder
// Captures execution traces
//============================================================================

class TraceRecorder {
public:
    struct Config {
        bool record_all_events;
        bool record_precision_snapshots;
        bool record_residency_snapshots;
        uint32_t snapshot_interval_ms;  // How often to take snapshots
        size_t max_trace_size_mb;       // Limit memory usage
        bool compress_traces;           // LZ4 compression
    };
    
    static Config DefaultConfig();
    
    explicit TraceRecorder(const Config& config);
    ~TraceRecorder();
    
    // Start/stop recording
    void StartRecording(uint64_t token_id);
    void StopRecording();
    bool IsRecording() const;
    
    // Record events
    void RecordTokenStart(const TokenStartEvent& event);
    void RecordTokenEnd(const TokenEndEvent& event);
    void RecordLayerStart(const LayerStartEvent& event);
    void RecordLayerEnd(const LayerEndEvent& event);
    void RecordKernelCall(const KernelCallEvent& event);
    void RecordPrecisionSelect(const PrecisionSelectEvent& event);
    void RecordResidencyTransition(const ResidencyTransitionEvent& event);
    void RecordPrefetchStart(const PrefetchEvent& event);
    void RecordPrefetchComplete(const PrefetchEvent& event);
    void RecordMemoryAccess(const MemoryAccessEvent& event);
    void RecordTLB(const TLBEvent& event);
    void RecordStall(const StallCycleEvent& event);
    void RecordErrorMetric(const ErrorMetricEvent& event);
    void RecordSampling(const SamplingEvent& event);
    
    // Take snapshots
    void SnapshotPrecisionMap(const PrecisionMapSnapshot& snapshot);
    void SnapshotResidencyMap(const ResidencyMapSnapshot& snapshot);
    
    // Get current trace
    TokenExecutionTrace* GetCurrentTrace();
    
    // Export
    bool ExportTrace(const std::string& path);
    bool ExportJSON(const std::string& path);
    bool ExportChromeTrace(const std::string& path);  // For chrome://tracing
    
    // Statistics
    struct Stats {
        uint64_t events_recorded;
        uint64_t snapshots_taken;
        uint64_t bytes_recorded;
        uint64_t tokens_traced;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::unique_ptr<TokenExecutionTrace> current_trace_;
    std::vector<std::unique_ptr<TokenExecutionTrace>> completed_traces_;
    
    std::mutex mutex_;
    bool recording_;
    
    Stats stats_;
    
    // Private methods
    uint64_t GetTimestampNs() const;
    void CheckMemoryLimit();
};

//============================================================================
// Trace Replayer
// Replays execution traces for debugging
//============================================================================

class TraceReplayer {
public:
    // Load trace from file
    bool LoadTrace(const std::string& path);
    
    // Replay control
    void StartReplay();
    void PauseReplay();
    void ResumeReplay();
    void StopReplay();
    
    // Step through trace
    void StepNext();           // Next event
    void StepPrevious();       // Previous event
    void StepToToken(uint64_t token_id);
    void StepToLayer(uint32_t layer_id);
    void StepToTime(uint64_t timestamp_ns);
    
    // Get current state
    const TraceEvent* GetCurrentEvent() const;
    const PrecisionMapSnapshot* GetCurrentPrecisionMap() const;
    const ResidencyMapSnapshot* GetCurrentResidencyMap() const;
    
    // Query
    std::vector<const TraceEvent*> FindEvents(TraceEventType type);
    std::vector<const TraceEvent*> FindEventsInRange(uint64_t start_ns, uint64_t end_ns);
    
    // Analysis
    struct Analysis {
        float avg_token_latency_ms;
        float avg_layer_latency_ms;
        uint32_t total_precision_switches;
        uint32_t total_stall_cycles;
        float prefetch_hit_rate;
        std::map<PrecisionMode, float> precision_distribution;
        std::map<ResidencyState, uint32_t> residency_distribution;
    };
    Analysis AnalyzeTrace() const;
    
    // Compare traces
    static bool CompareTraces(const std::string& trace1_path,
                               const std::string& trace2_path,
                               std::string& diff_report);
    
private:
    std::vector<std::unique_ptr<TokenExecutionTrace>> traces_;
    size_t current_trace_idx_;
    size_t current_event_idx_;
    
    bool replaying_;
    bool paused_;
};

//============================================================================
// Deterministic Execution Mode
// Ensures reproducible execution
//============================================================================

class DeterministicExecutionMode {
public:
    struct Config {
        uint64_t random_seed;
        bool fixed_precision;        // Disable adaptive precision
        PrecisionMode forced_precision;
        bool fixed_prefetch;         // Disable adaptive prefetch
        bool record_determinism_check; // Verify reproducibility
    };
    
    static Config DefaultConfig();
    
    explicit DeterministicExecutionMode(const Config& config);
    
    // Initialize for deterministic execution
    void Initialize();
    
    // Get deterministic random values
    float GetRandomFloat();
    uint32_t GetRandomInt();
    
    // Check if execution matches recorded trace
    bool CheckDeterminism(const TokenExecutionTrace& recorded,
                          const TokenExecutionTrace& current);
    
    // Generate determinism report
    bool GenerateReport(const std::string& path,
                        const std::vector<TokenExecutionTrace>& traces);
    
private:
    Config config_;
    std::mt19937 rng_;
};

//============================================================================
// C API for Tracing
//============================================================================

extern "C" {
    // Trace recording
    NEVM_EXPORT void* NEVM_Trace_CreateRecorder(int config_flags);
    NEVM_EXPORT void NEVM_Trace_DestroyRecorder(void* recorder);
    NEVM_EXPORT void NEVM_Trace_Start(void* recorder, uint64_t token_id);
    NEVM_EXPORT void NEVM_Trace_Stop(void* recorder);
    NEVM_EXPORT int NEVM_Trace_Export(void* recorder, const char* path);
    
    // Trace replay
    NEVM_EXPORT void* NEVM_Trace_Load(const char* path);
    NEVM_EXPORT void NEVM_Trace_Replay(void* trace);
    NEVM_EXPORT void NEVM_Trace_StepNext(void* trace);
    NEVM_EXPORT void NEVM_Trace_Analyze(void* trace, char* output, size_t output_size);
}

} // namespace NEVM
} // namespace RawrXD
