#pragma once
// ============================================================================
// Beaconism.hpp — Universal Causal Observation Layer
// Every tool call, agent dispatch, GPU submit, validator, and token phase
// emits the same causal beacon format for end-to-end traceability.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <string>
#include <atomic>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Beacon event types — exhaustive, fail-closed
// ---------------------------------------------------------------------------
enum class BeaconEvent : uint32_t {
    UNKNOWN = 0,
    // Token lifecycle
    TOKEN_BEGIN,
    TOKEN_LAYER_BEGIN,
    TOKEN_LAYER_END,
    TOKEN_END,
    // GPU lifecycle
    GPU_SUBMIT,
    GPU_COMPLETE,
    GPU_IDLE,
    GPU_HANDOFF_BEGIN,
    GPU_HANDOFF_END,
    GPU_QUEUE_DEPTH,
    GPU_RESIDENCY_UPDATE,
    // Tool lifecycle
    TOOL_CALL_BEGIN,
    TOOL_CALL_END,
    TOOL_CALL_FAIL,
    TOOL_CALL_REJECT,
    // Agent lifecycle
    AGENT_CREATE,
    AGENT_DESTROY,
    AGENT_TASK_BEGIN,
    AGENT_TASK_END,
    AGENT_TOOL_REQUEST,
    AGENT_TOOL_RESULT,
    // Validator lifecycle
    VALIDATOR_BEGIN,
    VALIDATOR_PASS,
    VALIDATOR_FAIL,
    // PowerShell lifecycle
    PS_BEGIN,
    PS_PASS,
    PS_FAIL,
    // Python lifecycle
    PY_BEGIN,
    PY_PASS,
    PY_FAIL,
    // Scheduling
    SCHEDULER_SELECT,
    SCHEDULER_SCORE,
    SCHEDULER_DECISION,
    // Manifestations (self-detected anomalies)
    MANIFEST_GPU0_IDLE_WITH_READY_WORK,
    MANIFEST_GPU1_IDLE_WITH_READY_WORK,
    MANIFEST_BAD_DEVICE_SELECTION,
    MANIFEST_EXCESSIVE_HANDOFF,
    MANIFEST_GPU_QUEUE_IMBALANCE,
    MANIFEST_GPU_RESIDENCY_MISS,
    MANIFEST_CROSS_GPU_COPY_STALL,
    MANIFEST_CPU_FALLBACK,
    MANIFEST_SSM_IDENTITY_FALLBACK,
    // SSM / selective scan
    SSM_BEGIN,
    SSM_GPU_DISPATCH,
    SSM_CPU_FALLBACK,
    SSM_IDENTITY_FALLBACK,
    SSM_COMPLETE,
    COUNT
};

// ---------------------------------------------------------------------------
// Causal beacon record — immutable once emitted
// ---------------------------------------------------------------------------
struct BeaconRecord {
    uint64_t seq = 0;                // Monotonic sequence number
    uint64_t timestampNs = 0;        // std::chrono::steady_clock nanos
    BeaconEvent event = BeaconEvent::UNKNOWN;
    uint64_t parentSeq = 0;          // Parent beacon seq (causal link)
    std::string requestId;           // User request correlation
    std::string agentId;             // Which agent produced this
    std::string toolId;              // Which tool (if any)
    uint32_t tokenId = 0;            // Token index (if inference)
    uint32_t layerId = 0;            // Layer index (if inference)
    std::string deviceId;            // GPU device name (if GPU event)
    std::string eventPhase;          // BEGIN / END / etc.
    std::string result;              // PASS / FAIL / etc.
    std::string reason;             // Human-readable failure reason
    uint64_t bytes = 0;              // Bytes transferred / resident
    uint64_t durationNs = 0;         // Event duration (if applicable)
    // Sparse key-value for extensibility
    std::unordered_map<std::string, std::string> fields;

    std::string toString() const;
    std::string toCompactString() const; // BEACON|SEQ=... format
};

// ---------------------------------------------------------------------------
// Beaconism authority — singleton, thread-safe, zero-allocation hot path
// ---------------------------------------------------------------------------
class BeaconismAuthority {
public:
    static BeaconismAuthority& Instance();

    // Open output streams (CSV + JSONL). Call once at init.
    bool open(const char* csvPath = nullptr, const char* jsonlPath = nullptr);
    void close();

    // Emit a beacon record. Thread-safe.
    void emit(const BeaconRecord& rec);

    // Convenience: emit with minimal args (auto-generates seq + timestamp)
    void emit(BeaconEvent event,
              uint64_t parentSeq = 0,
              const char* result = nullptr,
              const char* reason = nullptr,
              uint64_t bytes = 0,
              uint64_t durationNs = 0);

    // Manifestation: self-reported anomaly detection
    void manifest(BeaconEvent manifestationType,
                  const char* alternateDevice = nullptr,
                  const char* detail = nullptr);

    // Current monotonic sequence (for parent linking)
    uint64_t currentSeq() const;
    
    // Atomically increment and return next sequence number
    uint64_t nextSeq();

    // Snapshot of recent beacons (for live diagnostics)
    std::vector<BeaconRecord> recentBeacons(size_t maxCount = 100) const;

    // Analysis: compute scheduler loss from recent beacons
    struct SchedulerLossReport {
        uint64_t tokenCount = 0;
        uint64_t gpu0UsefulBusyUs = 0;
        uint64_t gpu1UsefulBusyUs = 0;
        uint64_t gpu1IdleWithReadyWorkUs = 0;
        uint64_t crossGpuHandoffs = 0;
        uint64_t handoffCostUs = 0;
        uint64_t schedulerLossUs = 0;
        std::string recommendedPolicy;
    };
    SchedulerLossReport analyzeSchedulerLoss() const;

    // Environment gate: DEEP2_BEACONISM=1 enables, =0 disables (default 0)
    static bool enabledGlobally();

private:
    BeaconismAuthority() = default;
    ~BeaconismAuthority() = default;
    BeaconismAuthority(const BeaconismAuthority&) = delete;
    BeaconismAuthority& operator=(const BeaconismAuthority&) = delete;

    mutable std::mutex mutex_;
    FILE* csvFp_ = nullptr;
    FILE* jsonlFp_ = nullptr;
    std::atomic<uint64_t> seq_{0};
    std::vector<BeaconRecord> ringBuffer_;
    static constexpr size_t kRingSize = 65536;
    size_t ringHead_ = 0;
    size_t ringCount_ = 0;

    void writeCsv(const BeaconRecord& rec);
    void writeJsonl(const BeaconRecord& rec);
    void pushRing(const BeaconRecord& rec);
};

// ---------------------------------------------------------------------------
// Scoped beacon guard — RAII for BEGIN/END pairs
// ---------------------------------------------------------------------------
class ScopedBeacon {
public:
    ScopedBeacon(BeaconEvent event,
                 uint64_t parentSeq = 0,
                 const char* result = nullptr);
    ~ScopedBeacon();

    void setResult(const char* result);
    void setBytes(uint64_t bytes);
    void setDurationNs(uint64_t ns);
    void addField(const char* key, const char* value);

private:
    BeaconRecord rec_;
    bool closed_ = false;
};

// ---------------------------------------------------------------------------
// PowerShell beacon wrapper (callable from C++ side)
// ---------------------------------------------------------------------------
struct PowerShellBeacon {
    static uint64_t begin(const char* command, uint64_t parentSeq = 0);
    static void pass(uint64_t beaconSeq, uint64_t durationMs = 0);
    static void fail(uint64_t beaconSeq, const char* error, uint64_t durationMs = 0);
};

// ---------------------------------------------------------------------------
// Validator beacon — structured validation records
// ---------------------------------------------------------------------------
struct ValidatorBeacon {
    static uint64_t begin(const char* validatorName,
                          const std::unordered_map<std::string, std::string>& expected,
                          uint64_t parentSeq = 0);
    static void pass(uint64_t beaconSeq);
    static void fail(uint64_t beaconSeq,
                     const std::unordered_map<std::string, std::string>& observed,
                     const char* reason);
};

// ---------------------------------------------------------------------------
// Convenience macros (zero-cost when disabled)
// ---------------------------------------------------------------------------
#define BEACON(event, ...) \
    do { if (Deep2::BeaconismAuthority::enabledGlobally()) \
         Deep2::BeaconismAuthority::Instance().emit(Deep2::BeaconEvent::event, __VA_ARGS__); } while(0)

#define BEACON_MANIFEST(type, ...) \
    do { if (Deep2::BeaconismAuthority::enabledGlobally()) \
         Deep2::BeaconismAuthority::Instance().manifest(Deep2::BeaconEvent::type, __VA_ARGS__); } while(0)

} // namespace Deep2
